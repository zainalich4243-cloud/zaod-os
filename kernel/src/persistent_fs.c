#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"
#include "persistent_fs.h"

#define FS_VERSION 1u
#define FS_DATA_SECTORS 4096u
#define FS_DATA_START (1u + PERSISTENT_FS_SLOT_COUNT)
#define FS_REQUIRED_SECTORS \
    (FS_DATA_START + PERSISTENT_FS_SLOT_COUNT * FS_DATA_SECTORS)
#define FS_RECORD_MAGIC "ZAODFIL1"
#define FS_VOLUME_MAGIC "ZAODFS01"
#define FS_PATH_CAPACITY 256u
#define FS_CRC_OFFSET 508u
#define FS_ERROR_NO_ENTRY 2
#define FS_ERROR_IO 5
#define FS_ERROR_INVALID 22
#define FS_ERROR_FILE_TOO_LARGE 27

struct fs_volume_record {
    char magic[8];
    uint32_t version;
    uint32_t slot_count;
    uint32_t data_sectors;
    uint32_t data_start;
    uint8_t reserved[FS_CRC_OFFSET - 24];
    uint32_t checksum;
} __attribute__((packed));

struct fs_file_record {
    char magic[8];
    uint32_t size;
    uint16_t path_length;
    uint16_t reserved0;
    char path[FS_PATH_CAPACITY];
    uint8_t reserved1[FS_CRC_OFFSET - 8 - 4 - 2 - 2 - FS_PATH_CAPACITY];
    uint32_t checksum;
} __attribute__((packed));

_Static_assert(sizeof(struct fs_volume_record) == BLOCK_SECTOR_SIZE,
               "ZAODFS superblock must occupy one sector");
_Static_assert(sizeof(struct fs_file_record) == BLOCK_SECTOR_SIZE,
               "ZAODFS file metadata must occupy one sector");

static bool mounted;

static uint32_t checksum32(const uint8_t *bytes, size_t size)
{
    uint32_t crc = 0xffffffffu;
    for (size_t index = 0; index < size; ++index) {
        crc ^= bytes[index];
        for (size_t bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

static size_t string_length(const char *text, size_t capacity)
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

static bool same_magic(const char magic[8], const char *expected)
{
    for (size_t index = 0; index < 8; ++index) {
        if (magic[index] != expected[index]) {
            return false;
        }
    }
    return true;
}

bool persistent_fs_path_allowed(const char *path)
{
    if (path == NULL || path[0] != '/') {
        return false;
    }
    size_t length = string_length(path, FS_PATH_CAPACITY);
    if (length < 7 || length >= FS_PATH_CAPACITY) {
        return false;
    }
    bool allowed_root =
        (path[1] == 'h' && path[2] == 'o' && path[3] == 'm' &&
         path[4] == 'e' && path[5] == '/') ||
        (length >= 16 && path[1] == 'o' && path[2] == 'p' && path[3] == 't' &&
         path[4] == '/' && path[5] == 'z' && path[6] == 'a' &&
         path[7] == 'o' && path[8] == 'd' && path[9] == '/' &&
         path[10] == 'a' && path[11] == 'p' && path[12] == 'p' &&
         path[13] == 's' && path[14] == '/');
    if (!allowed_root) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (path[index] == '\\' ||
            (path[index] == '/' &&
             (path[index + 1] == '/' || path[index + 1] == '\0'))) {
            return false;
        }
        if (path[index] == '/') {
            size_t component = index + 1;
            size_t component_length = 0;
            while (component + component_length < length &&
                   path[component + component_length] != '/') {
                ++component_length;
            }
            if ((component_length == 1 && path[component] == '.') ||
                (component_length == 2 && path[component] == '.' &&
                 path[component + 1] == '.')) {
                return false;
            }
        }
    }
    return true;
}

static uint64_t data_lba(size_t slot)
{
    return FS_DATA_START + (uint64_t)slot * FS_DATA_SECTORS;
}

static int64_t read_record(size_t slot, struct fs_file_record *record)
{
    if (slot >= PERSISTENT_FS_SLOT_COUNT ||
        !block_read_sector(1 + slot, (uint8_t *)record)) {
        return -FS_ERROR_IO;
    }
    if (record->magic[0] == '\0') {
        return -FS_ERROR_NO_ENTRY;
    }
    if (!same_magic(record->magic, FS_RECORD_MAGIC) ||
        record->size > PERSISTENT_FS_MAX_FILE_SIZE ||
        record->path_length == 0 ||
        record->path_length >= FS_PATH_CAPACITY ||
        record->path[record->path_length] != '\0' ||
        !persistent_fs_path_allowed(record->path)) {
        return -FS_ERROR_IO;
    }
    uint32_t stored_checksum = record->checksum;
    record->checksum = 0;
    uint32_t actual_checksum =
        checksum32((const uint8_t *)record, BLOCK_SECTOR_SIZE);
    record->checksum = stored_checksum;
    return stored_checksum == actual_checksum ? 0 : -FS_ERROR_IO;
}

static bool write_record(size_t slot, struct fs_file_record *record)
{
    record->checksum = 0;
    record->checksum = checksum32((const uint8_t *)record,
                                  BLOCK_SECTOR_SIZE);
    return block_write_sector(1 + slot, (const uint8_t *)record);
}

bool persistent_fs_format(void)
{
    if (block_sector_count() < FS_REQUIRED_SECTORS) {
        return false;
    }
    uint8_t sector[BLOCK_SECTOR_SIZE] = {0};
    struct fs_volume_record *volume = (struct fs_volume_record *)sector;
    for (size_t index = 0; index < sizeof(FS_VOLUME_MAGIC) - 1; ++index) {
        volume->magic[index] = FS_VOLUME_MAGIC[index];
    }
    volume->version = FS_VERSION;
    volume->slot_count = PERSISTENT_FS_SLOT_COUNT;
    volume->data_sectors = FS_DATA_SECTORS;
    volume->data_start = FS_DATA_START;
    volume->checksum = checksum32(sector, sizeof(sector));
    if (!block_write_sector(0, sector)) {
        return false;
    }
    for (size_t slot = 0; slot < PERSISTENT_FS_SLOT_COUNT; ++slot) {
        for (size_t index = 0; index < sizeof(sector); ++index) {
            sector[index] = 0;
        }
        if (!block_write_sector(1 + slot, sector)) {
            return false;
        }
    }
    mounted = false;
    return true;
}

bool persistent_fs_mount(void)
{
    mounted = false;
    if (block_sector_count() < FS_REQUIRED_SECTORS) {
        return false;
    }
    uint8_t sector[BLOCK_SECTOR_SIZE];
    if (!block_read_sector(0, sector)) {
        return false;
    }
    struct fs_volume_record *volume = (struct fs_volume_record *)sector;
    uint32_t stored_checksum = volume->checksum;
    volume->checksum = 0;
    uint32_t actual_checksum = checksum32(sector, sizeof(sector));
    volume->checksum = stored_checksum;
    if (!same_magic(volume->magic, FS_VOLUME_MAGIC) ||
        volume->version != FS_VERSION ||
        volume->slot_count != PERSISTENT_FS_SLOT_COUNT ||
        volume->data_sectors != FS_DATA_SECTORS ||
        volume->data_start != FS_DATA_START ||
        stored_checksum != actual_checksum) {
        return false;
    }
    for (size_t slot = 0; slot < PERSISTENT_FS_SLOT_COUNT; ++slot) {
        struct fs_file_record record;
        int64_t result = read_record(slot, &record);
        if (result != 0 && result != -FS_ERROR_NO_ENTRY) {
            return false;
        }
    }
    mounted = true;
    return true;
}

int64_t persistent_fs_open(const char *path, bool create, bool truncate,
                           size_t *slot, size_t *size)
{
    if (!mounted) {
        return -FS_ERROR_IO;
    }
    if (slot == NULL || size == NULL ||
        !persistent_fs_path_allowed(path)) {
        return -FS_ERROR_INVALID;
    }
    size_t length = string_length(path, FS_PATH_CAPACITY);
    size_t empty_slot = PERSISTENT_FS_SLOT_COUNT;
    for (size_t candidate = 0; candidate < PERSISTENT_FS_SLOT_COUNT;
         ++candidate) {
        struct fs_file_record record;
        int64_t result = read_record(candidate, &record);
        if (result == -FS_ERROR_NO_ENTRY) {
            if (empty_slot == PERSISTENT_FS_SLOT_COUNT) {
                empty_slot = candidate;
            }
            continue;
        }
        if (result != 0) {
            return result;
        }
        if (record.path_length == length &&
            same_string(record.path, path)) {
            if (truncate) {
                record.size = 0;
                if (!write_record(candidate, &record)) {
                    return -FS_ERROR_IO;
                }
            }
            *slot = candidate;
            *size = truncate ? 0 : record.size;
            return 0;
        }
    }
    if (!create) {
        return -FS_ERROR_NO_ENTRY;
    }
    if (empty_slot == PERSISTENT_FS_SLOT_COUNT) {
        return -FS_ERROR_FILE_TOO_LARGE;
    }
    struct fs_file_record record = {0};
    for (size_t index = 0; index < sizeof(FS_RECORD_MAGIC) - 1; ++index) {
        record.magic[index] = FS_RECORD_MAGIC[index];
    }
    record.path_length = (uint16_t)length;
    for (size_t index = 0; index <= length; ++index) {
        record.path[index] = path[index];
    }
    if (!write_record(empty_slot, &record)) {
        return -FS_ERROR_IO;
    }
    *slot = empty_slot;
    *size = 0;
    return 0;
}

bool persistent_fs_size(size_t slot, size_t *size)
{
    if (!mounted || size == NULL) {
        return false;
    }
    struct fs_file_record record;
    if (read_record(slot, &record) != 0) {
        return false;
    }
    *size = record.size;
    return true;
}

int64_t persistent_fs_read(size_t slot, size_t offset,
                           void *buffer, size_t size)
{
    if (!mounted || (buffer == NULL && size != 0)) {
        return -FS_ERROR_IO;
    }
    struct fs_file_record record;
    int64_t status = read_record(slot, &record);
    if (status != 0) {
        return status;
    }
    if (offset >= record.size) {
        return 0;
    }
    size_t amount = record.size - offset;
    if (amount > size) {
        amount = size;
    }
    uint8_t sector[BLOCK_SECTOR_SIZE];
    uint8_t *output = buffer;
    size_t copied = 0;
    while (copied < amount) {
        size_t position = offset + copied;
        size_t sector_index = position / BLOCK_SECTOR_SIZE;
        size_t sector_offset = position % BLOCK_SECTOR_SIZE;
        size_t chunk = BLOCK_SECTOR_SIZE - sector_offset;
        if (chunk > amount - copied) {
            chunk = amount - copied;
        }
        if (!block_read_sector(data_lba(slot) + sector_index, sector)) {
            return copied == 0 ? -FS_ERROR_IO : (int64_t)copied;
        }
        for (size_t index = 0; index < chunk; ++index) {
            output[copied + index] = sector[sector_offset + index];
        }
        copied += chunk;
    }
    return (int64_t)copied;
}

int64_t persistent_fs_write(size_t slot, size_t offset,
                            const void *buffer, size_t size)
{
    if (!mounted || (buffer == NULL && size != 0)) {
        return -FS_ERROR_IO;
    }
    struct fs_file_record record;
    int64_t status = read_record(slot, &record);
    if (status != 0) {
        return status;
    }
    if (offset > PERSISTENT_FS_MAX_FILE_SIZE ||
        size > PERSISTENT_FS_MAX_FILE_SIZE - offset ||
        offset > record.size) {
        return -FS_ERROR_FILE_TOO_LARGE;
    }
    const uint8_t *input = buffer;
    uint8_t sector[BLOCK_SECTOR_SIZE];
    size_t written = 0;
    while (written < size) {
        size_t position = offset + written;
        size_t sector_index = position / BLOCK_SECTOR_SIZE;
        size_t sector_offset = position % BLOCK_SECTOR_SIZE;
        size_t chunk = BLOCK_SECTOR_SIZE - sector_offset;
        if (chunk > size - written) {
            chunk = size - written;
        }
        if (sector_offset != 0 || chunk != BLOCK_SECTOR_SIZE) {
            if (!block_read_sector(data_lba(slot) + sector_index, sector)) {
                return written == 0 ? -FS_ERROR_IO : (int64_t)written;
            }
        }
        for (size_t index = 0; index < chunk; ++index) {
            sector[sector_offset + index] = input[written + index];
        }
        if (!block_write_sector(data_lba(slot) + sector_index, sector)) {
            return written == 0 ? -FS_ERROR_IO : (int64_t)written;
        }
        written += chunk;
    }
    size_t end = offset + written;
    if (end > record.size) {
        record.size = (uint32_t)end;
        if (!write_record(slot, &record)) {
            return -FS_ERROR_IO;
        }
    }
    return (int64_t)written;
}
