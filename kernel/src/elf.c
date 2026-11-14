#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "address_space.h"
#include "elf.h"
#include "memory.h"
#include "security.h"
#include "task.h"
#include "zshield.h"

#define ELF_CLASS_64 2u
#define ELF_DATA_LITTLE_ENDIAN 1u
#define ELF_TYPE_EXEC 2u
#define ELF_MACHINE_X86_64 62u
#define ELF_PROGRAM_LOAD 1u
#define ELF_FLAG_EXECUTE 1u
#define ELF_FLAG_WRITE 2u
#define ELF_MAX_PROGRAM_HEADERS 128u
#define ELF_MAX_IMAGE_SIZE (16u * 1024u * 1024u)
#define ELF_USER_ADDRESS_LIMIT 0x0000800000000000ull
#define ELF_STACK_TOP 0x00007ffffff00000ull
#define ELF_STACK_PAGES 4u
#define ELF_PAGE_SIZE 4096u
#define ELF_PAGE_MASK (ELF_PAGE_SIZE - 1u)
#define ELF_USER_STACK_FLAGS ADDRESS_SPACE_WRITE

struct elf64_header {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_header_offset;
    uint64_t section_header_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t program_header_size;
    uint16_t program_header_count;
    uint16_t section_header_size;
    uint16_t section_header_count;
    uint16_t section_name_index;
} __attribute__((packed));

struct elf64_program_header {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} __attribute__((packed));

static bool range_within(uint64_t offset, uint64_t length, size_t total)
{
    return offset <= total && length <= total - (size_t)offset;
}

static bool copy_segment(struct address_space *space,
                         const uint8_t *image,
                         const struct elf64_program_header *segment)
{
    if (segment->memory_size == 0 ||
        segment->file_size > segment->memory_size ||
        segment->virtual_address < ELF_PAGE_SIZE ||
        segment->virtual_address >= ELF_USER_ADDRESS_LIMIT ||
        segment->memory_size > ELF_USER_ADDRESS_LIMIT -
                                   segment->virtual_address ||
        segment->file_size > SIZE_MAX) {
        return false;
    }
    uint64_t end = segment->virtual_address + segment->memory_size;
    uint64_t first_page = segment->virtual_address & ~(uint64_t)ELF_PAGE_MASK;
    uint64_t last_page = (end - 1) & ~(uint64_t)ELF_PAGE_MASK;
    uint32_t page_flags = 0;
    if ((segment->flags & ELF_FLAG_WRITE) != 0) {
        page_flags |= ADDRESS_SPACE_WRITE;
    }
    if ((segment->flags & ELF_FLAG_EXECUTE) != 0) {
        page_flags |= ADDRESS_SPACE_EXECUTE;
    }

    for (uint64_t page = first_page;; page += ELF_PAGE_SIZE) {
        if (!address_space_map_page(space, (uintptr_t)page, page_flags, NULL)) {
            return false;
        }
        if (page == last_page) {
            break;
        }
        if (page > UINT64_MAX - ELF_PAGE_SIZE) {
            return false;
        }
    }

    uint64_t source_offset = 0;
    while (source_offset < segment->file_size) {
        uint64_t destination_address = segment->virtual_address + source_offset;
        uint64_t page_offset = destination_address & ELF_PAGE_MASK;
        uint64_t amount = ELF_PAGE_SIZE - page_offset;
        uint64_t remaining = segment->file_size - source_offset;
        if (amount > remaining) {
            amount = remaining;
        }

        uintptr_t virtual_page =
            (uintptr_t)(destination_address & ~(uint64_t)ELF_PAGE_MASK);
        uint64_t physical_page;
        if (!address_space_page_physical(space, virtual_page,
                                         &physical_page)) {
            return false;
        }
        uint8_t *destination = memory_phys_to_virt(physical_page);
        if (destination == NULL) {
            return false;
        }
        destination += page_offset;
        for (uint64_t index = 0; index < amount; ++index) {
            destination[index] =
                image[segment->offset + source_offset + index];
        }
        source_offset += amount;
    }
    return true;
}

static bool elf64_spawn_image(const char *app_id, bool system_task,
                              bool package_verified,
                              const uint8_t *image, size_t image_size,
                              uint64_t *pid)
{
    const struct security_subject init_subject = {
        .pid = 1,
        .uid = 0,
        .capabilities = SECURITY_CAP_SYSTEM
    };
    struct security_subject app_subject = {
        .pid = task_current_pid(),
        .uid = 1000,
        .capabilities = 0,
        .app_id = app_id
    };
    char app_path[128] = "/opt/zaod/apps/";
    size_t app_path_length = sizeof("/opt/zaod/apps/") - 1;
    if (package_verified && app_id != NULL) {
        size_t app_id_length = 0;
        while (app_id[app_id_length] != '\0' &&
               app_id_length < TASK_APP_ID_CAPACITY - 1) {
            app_path[app_path_length++] = app_id[app_id_length++];
        }
        static const char suffix[] = "/bin/app";
        if (app_id[app_id_length] != '\0' ||
            app_path_length + sizeof(suffix) > sizeof(app_path)) {
            return false;
        }
        for (size_t index = 0; index < sizeof(suffix); ++index) {
            app_path[app_path_length++] = suffix[index];
        }
    }
    bool trusted_entry = system_task && app_id == NULL &&
        !package_verified &&
        zshield_verify_trusted_init(image, image_size) &&
        security_check(SECURITY_OP_EXEC, &init_subject,
                       "/sbin/init.elf", true) == SECURITY_DECISION_ALLOW;
    bool trusted_package = !system_task && app_id != NULL &&
        package_verified && zshield_catalog_ready() &&
        security_check(SECURITY_OP_EXEC, &app_subject, app_path, true) ==
            SECURITY_DECISION_ALLOW;
    if ((!trusted_entry && !trusted_package) ||
        image_size < sizeof(struct elf64_header) ||
        image_size > ELF_MAX_IMAGE_SIZE ||
        image == NULL) {
        return false;
    }
    const struct elf64_header *header =
        (const struct elf64_header *)image;
    if (header->ident[0] != 0x7f || header->ident[1] != 'E' ||
        header->ident[2] != 'L' || header->ident[3] != 'F' ||
        header->ident[4] != ELF_CLASS_64 ||
        header->ident[5] != ELF_DATA_LITTLE_ENDIAN ||
        header->ident[6] != 1 || header->type != ELF_TYPE_EXEC ||
        header->machine != ELF_MACHINE_X86_64 || header->version != 1 ||
        header->header_size != sizeof(*header) ||
        header->program_header_size != sizeof(struct elf64_program_header) ||
        header->program_header_count == 0 ||
        header->program_header_count > ELF_MAX_PROGRAM_HEADERS ||
        !range_within(header->program_header_offset,
                      (uint64_t)header->program_header_count *
                          sizeof(struct elf64_program_header),
                      image_size)) {
        return false;
    }

    struct address_space space;
    if (!address_space_create(&space)) {
        return false;
    }
    bool entry_is_executable = false;
    uint64_t mapped_memory = 0;
    for (size_t index = 0; index < header->program_header_count; ++index) {
        const struct elf64_program_header *segment =
            (const struct elf64_program_header *)(image +
                header->program_header_offset +
                index * sizeof(struct elf64_program_header));
        if (segment->type != ELF_PROGRAM_LOAD) {
            continue;
        }
        if (segment->memory_size == 0) {
            if (segment->file_size != 0) {
                return false;
            }
            continue;
        }
        if ((segment->flags & 4u) == 0 || (segment->flags & ~7u) != 0 ||
            (segment->flags & (ELF_FLAG_WRITE | ELF_FLAG_EXECUTE)) ==
                (ELF_FLAG_WRITE | ELF_FLAG_EXECUTE) ||
            !range_within(segment->offset, segment->file_size, image_size) ||
            (segment->alignment > 1 &&
             ((segment->alignment & (segment->alignment - 1)) != 0 ||
              segment->virtual_address % segment->alignment !=
                  segment->offset % segment->alignment)) ||
            segment->virtual_address % ELF_PAGE_SIZE !=
                segment->offset % ELF_PAGE_SIZE) {
            return false;
        }
        if (segment->memory_size > ELF_MAX_IMAGE_SIZE - mapped_memory) {
            return false;
        }
        mapped_memory += segment->memory_size;
        if ((segment->flags & ELF_FLAG_EXECUTE) != 0 &&
            header->entry >= segment->virtual_address &&
            header->entry - segment->virtual_address < segment->file_size) {
            entry_is_executable = true;
        }
        if (!copy_segment(&space, image, segment)) {
            return false;
        }
    }
    if (!entry_is_executable) {
        return false;
    }

    uint64_t stack_page_physical = 0;
    for (size_t page = 0; page < ELF_STACK_PAGES; ++page) {
        uintptr_t virtual_page = ELF_STACK_TOP -
            (ELF_STACK_PAGES - page) * ELF_PAGE_SIZE;
        if (!address_space_map_page(&space, virtual_page,
                                    ELF_USER_STACK_FLAGS,
                                    &stack_page_physical)) {
            return false;
        }
    }
    uint8_t *stack_page = memory_phys_to_virt(stack_page_physical);
    if (stack_page == NULL) {
        return false;
    }
    *(uint64_t *)(stack_page + ELF_PAGE_SIZE - sizeof(uint64_t)) = 0;
    return task_spawn_user(app_id, system_task, space.root_physical,
                          (uintptr_t)header->entry,
                          ELF_STACK_TOP - sizeof(uint64_t), pid);
}

bool elf64_spawn(const char *app_id, bool system_task,
                 const uint8_t *image, size_t image_size, uint64_t *pid)
{
    return elf64_spawn_image(app_id, system_task, false, image,
                             image_size, pid);
}

bool elf64_spawn_verified_app(const char *app_id,
                              const uint8_t *image, size_t image_size,
                              uint64_t *pid)
{
    return elf64_spawn_image(app_id, false, true, image, image_size, pid);
}
