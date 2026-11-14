#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "permissions.h"
#include "persistent_fs.h"
#include "sha256.h"
#include "security.h"
#include "task.h"
#include "vfs.h"
#include "zshield.h"

#define VFS_ENTRY_CAPACITY 256
#define VFS_DESCRIPTOR_CAPACITY 32
#define VFS_APP_DATA_CAPACITY 32
#define VFS_PATH_CAPACITY 256
#define VFS_APP_DATA_BYTES 4096

#define ERROR_BAD_FD 9
#define ERROR_FAULT 14
#define ERROR_INVALID 22
#define ERROR_TOO_MANY_FILES 24
#define ERROR_FILE_TOO_LARGE 27
#define ERROR_NO_ENTRY 2
#define ERROR_PERMISSION 13

struct archive_entry {
    char path[VFS_PATH_CAPACITY];
    const uint8_t *data;
    size_t size;
};

struct app_data_entry {
    bool used;
    char path[VFS_PATH_CAPACITY];
    uint8_t data[VFS_APP_DATA_BYTES];
    size_t size;
};

struct open_descriptor {
    bool used;
    bool writable;
    bool persistent;
    uint64_t owner_pid;
    const uint8_t *read_data;
    size_t size;
    size_t offset;
    size_t app_data_index;
    size_t persistent_slot;
    char path[VFS_PATH_CAPACITY];
};

static struct archive_entry archive_entries[VFS_ENTRY_CAPACITY];
static size_t archive_entry_count;
static struct app_data_entry app_data[VFS_APP_DATA_CAPACITY];
static struct open_descriptor descriptors[VFS_DESCRIPTOR_CAPACITY];
static bool vfs_ready;

static size_t bounded_length(const char *text, size_t capacity)
{
    size_t length = 0;
    while (length < capacity && text[length] != '\0') {
        ++length;
    }
    return length;
}

static bool same_string(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && left[index] == right[index]) {
        ++index;
    }
    return left[index] == '\0' && right[index] == '\0';
}

static bool copy_path(char destination[VFS_PATH_CAPACITY], const char *source)
{
    if (source == NULL || source[0] != '/') {
        return false;
    }
    size_t length = bounded_length(source, VFS_PATH_CAPACITY);
    if (length == 0 || length >= VFS_PATH_CAPACITY) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        destination[i] = source[i];
    }
    destination[length] = '\0';
    return true;
}

static bool parse_hex32(const uint8_t *field, uint32_t *value)
{
    uint32_t result = 0;
    for (size_t i = 0; i < 8; ++i) {
        uint8_t digit = field[i];
        uint8_t part;
        if (digit >= '0' && digit <= '9') {
            part = digit - '0';
        } else if (digit >= 'a' && digit <= 'f') {
            part = digit - 'a' + 10;
        } else if (digit >= 'A' && digit <= 'F') {
            part = digit - 'A' + 10;
        } else {
            return false;
        }
        result = (result << 4) | part;
    }
    *value = result;
    return true;
}

static bool path_is_canonical(const char *path)
{
    if (path[0] != '/') {
        return false;
    }
    for (size_t i = 0; path[i] != '\0'; ++i) {
        if (path[i] == '/' && path[i + 1] == '/') {
            return false;
        }
        if (path[i] == '/') {
            size_t start = i + 1;
            size_t length = 0;
            while (path[start + length] != '\0' &&
                   path[start + length] != '/') {
                ++length;
            }
            if ((length == 1 && path[start] == '.') ||
                (length == 2 && path[start] == '.' &&
                 path[start + 1] == '.')) {
                return false;
            }
        }
    }
    return true;
}

static bool app_data_path(const char *path, const char *app_id)
{
    static const char root[] = "/var/lib/zaod/apps/";
    if (app_id == NULL) {
        return false;
    }
    size_t root_length = sizeof(root) - 1;
    for (size_t i = 0; i < root_length; ++i) {
        if (path[i] != root[i]) {
            return false;
        }
    }
    size_t app_length = bounded_length(app_id, TASK_APP_ID_CAPACITY);
    if (app_length == 0 || app_length >= TASK_APP_ID_CAPACITY) {
        return false;
    }
    for (size_t i = 0; i < app_length; ++i) {
        if (path[root_length + i] != app_id[i]) {
            return false;
        }
    }
    if (path[root_length + app_length] != '/') {
        return false;
    }
    const char *filename = path + root_length + app_length + 1;
    if (filename[0] == '\0' || filename[0] == '.') {
        return false;
    }
    for (size_t i = 0; filename[i] != '\0'; ++i) {
        if (filename[i] == '/' || filename[i] == '\\') {
            return false;
        }
    }
    return true;
}

static bool current_subject(struct security_subject *subject)
{
    uint64_t pid = task_current_pid();
    bool system_task = task_current_is_system();
    const char *app_id = task_current_app_id();
    if (subject == NULL || pid == 0 || (!system_task && app_id == NULL)) {
        return false;
    }
    *subject = (struct security_subject) {
        .pid = pid,
        .uid = system_task ? 0 : 1000,
        .capabilities = system_task ? SECURITY_CAP_SYSTEM : 0,
        .app_id = app_id
    };
    return true;
}

bool vfs_init(const void *initramfs, size_t size)
{
    const uint8_t *bytes = initramfs;
    archive_entry_count = 0;
    for (size_t i = 0; i < VFS_APP_DATA_CAPACITY; ++i) {
        app_data[i].used = false;
    }
    for (size_t i = 0; i < VFS_DESCRIPTOR_CAPACITY; ++i) {
        descriptors[i].used = false;
    }
    vfs_ready = false;
    if (bytes == NULL) {
        return false;
    }

    size_t offset = 0;
    bool trailer_found = false;
    while (offset < size) {
        if (size - offset < 110) {
            return false;
        }
        const uint8_t *header = bytes + offset;
        if (header[0] != '0' || header[1] != '7' ||
            header[2] != '0' || header[3] != '7' || header[4] != '0' ||
            header[5] != '1') {
            return false;
        }
        uint32_t mode;
        uint32_t file_size;
        uint32_t name_size;
        if (!parse_hex32(header + 14, &mode) ||
            !parse_hex32(header + 54, &file_size) ||
            !parse_hex32(header + 94, &name_size) ||
            name_size == 0) {
            return false;
        }
        offset += 110;
        if (name_size > VFS_PATH_CAPACITY ||
            name_size > size - offset ||
            bytes[offset + name_size - 1] != '\0') {
            return false;
        }
        const char *name = (const char *)(bytes + offset);
        size_t name_length = name_size - 1;
        for (size_t i = 0; i < name_length; ++i) {
            if (name[i] == '\0') {
                return false;
            }
        }
        size_t name_end = offset + name_size;
        if (name_end > SIZE_MAX - 3u) {
            return false;
        }
        offset = (name_end + 3u) & ~(size_t)3u;
        if (offset > size) {
            return false;
        }
        if (file_size > size - offset) {
            return false;
        }
        if (same_string(name, "TRAILER!!!")) {
            if (file_size != 0) {
                return false;
            }
            trailer_found = true;
            break;
        }
        if (name_length == 0 || name[0] == '/' ||
            (name_length >= 2 && name[0] == '.' && name[1] == '.')) {
            return false;
        }
        char absolute_path[VFS_PATH_CAPACITY];
        if (name_length + 2 > sizeof(absolute_path)) {
            return false;
        }
        absolute_path[0] = '/';
        for (size_t i = 0; i < name_length; ++i) {
            absolute_path[i + 1] = name[i];
        }
        absolute_path[name_length + 1] = '\0';
        if (!path_is_canonical(absolute_path)) {
            return false;
        }
        uint32_t file_type = mode & 0170000u;
        if (file_type == 0100000u) {
            if (archive_entry_count == VFS_ENTRY_CAPACITY) {
                return false;
            }
            for (size_t i = 0; i < archive_entry_count; ++i) {
                if (same_string(archive_entries[i].path, absolute_path)) {
                    return false;
                }
            }
            struct archive_entry *entry =
                &archive_entries[archive_entry_count++];
            size_t path_length = name_length + 2;
            for (size_t i = 0; i < path_length; ++i) {
                entry->path[i] = absolute_path[i];
            }
            entry->data = bytes + offset;
            entry->size = file_size;
        } else if (file_type != 0040000u) {
            return false;
        }
        size_t data_end = offset + file_size;
        if (data_end > SIZE_MAX - 3u) {
            return false;
        }
        offset = (data_end + 3u) & ~(size_t)3u;
        if (offset > size) {
            return false;
        }
    }
    if (!trailer_found) {
        return false;
    }
    for (size_t i = offset; i < size; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    vfs_ready = true;
    return true;
}

static size_t find_archive_file(const char *path)
{
    for (size_t i = 0; i < archive_entry_count; ++i) {
        if (same_string(archive_entries[i].path, path)) {
            return i;
        }
    }
    return VFS_ENTRY_CAPACITY;
}

bool vfs_kernel_file(const char *path, const uint8_t **data, size_t *size)
{
    if (!vfs_ready || path == NULL || data == NULL || size == NULL) {
        return false;
    }
    size_t index = find_archive_file(path);
    if (index == VFS_ENTRY_CAPACITY) {
        return false;
    }
    *data = archive_entries[index].data;
    *size = archive_entries[index].size;
    return true;
}

static size_t find_app_data(const char *path)
{
    for (size_t i = 0; i < VFS_APP_DATA_CAPACITY; ++i) {
        if (app_data[i].used && same_string(app_data[i].path, path)) {
            return i;
        }
    }
    return VFS_APP_DATA_CAPACITY;
}

int64_t vfs_open(const char *path, uint32_t flags)
{
    const uint32_t known_flags =
        VFS_OPEN_READ | VFS_OPEN_WRITE | VFS_OPEN_CREATE | VFS_OPEN_TRUNCATE;
    if (!vfs_ready) {
        return -ERROR_NO_ENTRY;
    }
    if (flags == 0 || (flags & ~known_flags) != 0 ||
        ((flags & VFS_OPEN_READ) != 0 && (flags & VFS_OPEN_WRITE) != 0) ||
        ((flags & (VFS_OPEN_CREATE | VFS_OPEN_TRUNCATE)) != 0 &&
         (flags & VFS_OPEN_WRITE) == 0)) {
        return -ERROR_INVALID;
    }

    char canonical_path[VFS_PATH_CAPACITY];
    if (!copy_path(canonical_path, path) ||
        !path_is_canonical(canonical_path)) {
        return -ERROR_INVALID;
    }
    struct security_subject subject;
    if (!current_subject(&subject)) {
        return -ERROR_PERMISSION;
    }
    bool writing = (flags & VFS_OPEN_WRITE) != 0;
    if (!subject.capabilities && !permission_has_grant(
            subject.pid, PERMISSION_STORAGE)) {
        return -ERROR_PERMISSION;
    }
    enum security_decision decision = security_check(
        writing ? SECURITY_OP_FILE_WRITE : SECURITY_OP_FILE_READ,
        &subject, canonical_path, false);
    if (decision != SECURITY_DECISION_ALLOW) {
        return -ERROR_PERMISSION;
    }

    size_t descriptor_index = VFS_DESCRIPTOR_CAPACITY;
    for (size_t i = 0; i < VFS_DESCRIPTOR_CAPACITY; ++i) {
        if (!descriptors[i].used) {
            descriptor_index = i;
            break;
        }
    }
    if (descriptor_index == VFS_DESCRIPTOR_CAPACITY) {
        return -ERROR_TOO_MANY_FILES;
    }

    size_t app_data_index = VFS_APP_DATA_CAPACITY;
    size_t persistent_slot = 0;
    bool persistent = false;
    const uint8_t *data = NULL;
    size_t length = 0;
    if (writing) {
        if (app_data_path(canonical_path, subject.app_id)) {
            app_data_index = find_app_data(canonical_path);
            if (app_data_index == VFS_APP_DATA_CAPACITY) {
                if ((flags & VFS_OPEN_CREATE) == 0) {
                    return -ERROR_NO_ENTRY;
                }
                for (size_t i = 0; i < VFS_APP_DATA_CAPACITY; ++i) {
                    if (!app_data[i].used) {
                        app_data_index = i;
                        app_data[i].used = true;
                        app_data[i].size = 0;
                        size_t path_length = bounded_length(
                            canonical_path, VFS_PATH_CAPACITY);
                        for (size_t j = 0; j <= path_length; ++j) {
                            app_data[i].path[j] = canonical_path[j];
                        }
                        break;
                    }
                }
            }
            if (app_data_index == VFS_APP_DATA_CAPACITY) {
                return -ERROR_TOO_MANY_FILES;
            }
            data = app_data[app_data_index].data;
            length = app_data[app_data_index].size;
        } else if ((subject.capabilities & SECURITY_CAP_SYSTEM) != 0 &&
                   persistent_fs_path_allowed(canonical_path)) {
            int64_t opened = persistent_fs_open(
                canonical_path, (flags & VFS_OPEN_CREATE) != 0,
                (flags & VFS_OPEN_TRUNCATE) != 0,
                &persistent_slot, &length);
            if (opened < 0) {
                return opened;
            }
            persistent = true;
        } else {
            return -ERROR_PERMISSION;
        }
    } else {
        size_t data_index = app_data_path(canonical_path, subject.app_id)
            ? find_app_data(canonical_path)
            : VFS_APP_DATA_CAPACITY;
        if (data_index != VFS_APP_DATA_CAPACITY) {
            app_data_index = data_index;
            data = app_data[data_index].data;
            length = app_data[data_index].size;
        } else {
            size_t archive_index = find_archive_file(canonical_path);
            if (archive_index == VFS_ENTRY_CAPACITY) {
                if (!persistent_fs_path_allowed(canonical_path)) {
                    return -ERROR_NO_ENTRY;
                }
                int64_t opened = persistent_fs_open(
                    canonical_path, false, false,
                    &persistent_slot, &length);
                if (opened < 0) {
                    return opened;
                }
                persistent = true;
            } else {
                data = archive_entries[archive_index].data;
                length = archive_entries[archive_index].size;
            }
        }
    }

    if (writing && !persistent && (flags & VFS_OPEN_TRUNCATE) != 0) {
        app_data[app_data_index].size = 0;
        length = 0;
    }
    descriptors[descriptor_index] = (struct open_descriptor) {
        .used = true,
        .writable = writing,
        .persistent = persistent,
        .owner_pid = subject.pid,
        .read_data = data,
        .size = length,
        .offset = 0,
        .app_data_index = app_data_index,
        .persistent_slot = persistent_slot,
        .path = {0}
    };
    size_t path_length = bounded_length(canonical_path, VFS_PATH_CAPACITY);
    for (size_t index = 0; index <= path_length; ++index) {
        descriptors[descriptor_index].path[index] = canonical_path[index];
    }
    return (int64_t)descriptor_index;
}

int64_t vfs_read(int64_t descriptor, void *buffer, size_t size)
{
    if (descriptor < 0 || descriptor >= VFS_DESCRIPTOR_CAPACITY ||
        !descriptors[descriptor].used ||
        descriptors[descriptor].owner_pid != task_current_pid()) {
        return -ERROR_BAD_FD;
    }
    if (buffer == NULL && size != 0) {
        return -ERROR_FAULT;
    }
    struct open_descriptor *file = &descriptors[descriptor];
    if (file->writable) {
        return -ERROR_INVALID;
    }
    if (file->persistent) {
        int64_t amount = persistent_fs_read(
            file->persistent_slot, file->offset, buffer, size);
        if (amount > 0) {
            file->offset += (size_t)amount;
        }
        return amount;
    }
    size_t current_size = file->size;
    if (file->app_data_index < VFS_APP_DATA_CAPACITY) {
        current_size = app_data[file->app_data_index].size;
    }
    size_t remaining = file->offset < current_size
        ? current_size - file->offset
        : 0;
    size_t amount = size < remaining ? size : remaining;
    uint8_t *destination = buffer;
    for (size_t i = 0; i < amount; ++i) {
        destination[i] = file->read_data[file->offset + i];
    }
    file->offset += amount;
    return (int64_t)amount;
}

int64_t vfs_write(int64_t descriptor, const void *buffer, size_t size)
{
    if (descriptor < 0 || descriptor >= VFS_DESCRIPTOR_CAPACITY ||
        !descriptors[descriptor].used ||
        descriptors[descriptor].owner_pid != task_current_pid()) {
        return -ERROR_BAD_FD;
    }
    if (buffer == NULL && size != 0) {
        return -ERROR_FAULT;
    }
    struct open_descriptor *file = &descriptors[descriptor];
    if (!file->writable) {
        return -ERROR_INVALID;
    }
    if (!zshield_catalog_ready()) {
        struct security_subject subject;
        if (current_subject(&subject)) {
            security_report_blocked_write(&subject, file->path);
        }
        return -ERROR_PERMISSION;
    }
    if (file->persistent) {
        bool blocked = false;
        uint8_t sector[512];
        struct sha256_context hash;
        size_t old_size;
        if (!persistent_fs_size(file->persistent_slot, &old_size)) {
            return -5;
        }
        if (file->offset <= old_size &&
            size <= PERSISTENT_FS_MAX_FILE_SIZE - file->offset) {
            size_t end = file->offset + size;
            size_t candidate_size = end > old_size ? end : old_size;
            sha256_init(&hash);
            size_t cursor = 0;
            while (cursor < candidate_size) {
                if (cursor >= file->offset && cursor < end) {
                    size_t amount = end - cursor;
                    if (amount > sizeof(sector)) {
                        amount = sizeof(sector);
                    }
                    const uint8_t *source = buffer;
                    sha256_update(&hash, source + cursor - file->offset,
                                  amount);
                    cursor += amount;
                    continue;
                }
                size_t boundary = cursor < file->offset
                    ? file->offset
                    : candidate_size;
                size_t amount = boundary - cursor;
                if (amount > sizeof(sector)) {
                    amount = sizeof(sector);
                }
                int64_t read = persistent_fs_read(
                    file->persistent_slot, cursor, sector, amount);
                if (read != (int64_t)amount) {
                    return -5;
                }
                sha256_update(&hash, sector, amount);
                cursor += amount;
            }
            uint8_t digest[SHA256_DIGEST_SIZE];
            sha256_final(&hash, digest);
            blocked = zshield_digest_is_known(digest, NULL);
        }
        if (blocked) {
            struct security_subject subject;
            if (current_subject(&subject)) {
                security_report_blocked_write(&subject, file->path);
            }
            return -ERROR_PERMISSION;
        }
        int64_t amount = persistent_fs_write(
            file->persistent_slot, file->offset, buffer, size);
        if (amount > 0) {
            file->offset += (size_t)amount;
            (void)persistent_fs_size(file->persistent_slot, &file->size);
        }
        return amount;
    }
    if (file->app_data_index >= VFS_APP_DATA_CAPACITY) {
        return -ERROR_INVALID;
    }
    struct app_data_entry *entry = &app_data[file->app_data_index];
    if (file->offset > VFS_APP_DATA_BYTES ||
        size > VFS_APP_DATA_BYTES - file->offset) {
        return -ERROR_FILE_TOO_LARGE;
    }
    size_t end = file->offset + size;
    size_t candidate_size = end > entry->size ? end : entry->size;
    uint8_t candidate[VFS_APP_DATA_BYTES];
    for (size_t index = 0; index < entry->size; ++index) {
        candidate[index] = entry->data[index];
    }
    const uint8_t *source = buffer;
    for (size_t index = 0; index < size; ++index) {
        candidate[file->offset + index] = source[index];
    }
    if (zshield_scan_bytes(candidate, candidate_size, NULL)) {
        struct security_subject subject;
        if (current_subject(&subject)) {
            security_report_blocked_write(&subject, file->path);
        }
        return -ERROR_PERMISSION;
    }
    for (size_t i = 0; i < size; ++i) {
        entry->data[file->offset + i] = source[i];
    }
    file->offset += size;
    if (file->offset > entry->size) {
        entry->size = file->offset;
    }
    file->size = entry->size;
    return (int64_t)size;
}

void vfs_close(int64_t descriptor)
{
    if (descriptor >= 0 && descriptor < VFS_DESCRIPTOR_CAPACITY &&
        descriptors[descriptor].used &&
        descriptors[descriptor].owner_pid == task_current_pid()) {
        descriptors[descriptor].used = false;
    }
}

void vfs_close_process(uint64_t pid)
{
    for (size_t i = 0; i < VFS_DESCRIPTOR_CAPACITY; ++i) {
        if (descriptors[i].used && descriptors[i].owner_pid == pid) {
            descriptors[i].used = false;
        }
    }
}
