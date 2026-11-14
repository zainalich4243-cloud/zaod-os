#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "address_space.h"
#include "memory.h"

#define PAGE_SIZE 4096u
#define PAGE_MASK ((uint64_t)PAGE_SIZE - 1u)
#define ENTRY_PRESENT (1ull << 0)
#define ENTRY_WRITE (1ull << 1)
#define ENTRY_USER (1ull << 2)
#define ENTRY_LARGE (1ull << 7)
#define ENTRY_NO_EXECUTE (1ull << 63)
#define USER_ADDRESS_LIMIT 0x0000800000000000ull
#define USER_ROOT_INDEX_LIMIT 256u

static uint64_t kernel_root;

static uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value & ~PAGE_MASK;
}

uint64_t address_space_kernel_root(void)
{
    return kernel_root;
}

bool address_space_create(struct address_space *space)
{
    if (space == NULL || kernel_root == 0) {
        return false;
    }

    uint64_t new_root_physical;
    uint64_t *new_root = memory_alloc_page(&new_root_physical);
    uint64_t *current_root = memory_phys_to_virt(kernel_root);
    if (new_root == NULL || current_root == NULL) {
        return false;
    }

    for (size_t index = USER_ROOT_INDEX_LIMIT; index < 512; ++index) {
        new_root[index] = current_root[index];
    }
    space->root_physical = new_root_physical;
    return true;
}

static uint64_t *table_entry(uint64_t *table, size_t index)
{
    uint64_t entry = table[index];
    if ((entry & ENTRY_PRESENT) == 0 || (entry & ENTRY_LARGE) != 0) {
        return NULL;
    }
    return memory_phys_to_virt(entry & ~PAGE_MASK);
}

bool address_space_map_page(struct address_space *space,
                            uintptr_t virtual_address, uint32_t flags,
                            uint64_t *physical_address)
{
    if (space == NULL || space->root_physical == 0 ||
        (virtual_address & PAGE_MASK) != 0 ||
        virtual_address < PAGE_SIZE ||
        (uint64_t)virtual_address >= USER_ADDRESS_LIMIT ||
        (flags & ~(ADDRESS_SPACE_WRITE | ADDRESS_SPACE_EXECUTE)) != 0) {
        return false;
    }

    uint64_t *table = memory_phys_to_virt(space->root_physical);
    if (table == NULL) {
        return false;
    }

    const size_t indices[3] = {
        (virtual_address >> 39) & 0x1ffu,
        (virtual_address >> 30) & 0x1ffu,
        (virtual_address >> 21) & 0x1ffu
    };
    for (size_t level = 0; level < 3; ++level) {
        size_t index = indices[level];
        if ((table[index] & ENTRY_PRESENT) == 0) {
            uint64_t table_physical;
            uint64_t *new_table = memory_alloc_page(&table_physical);
            if (new_table == NULL) {
                return false;
            }
            table[index] = table_physical |
                           ENTRY_PRESENT | ENTRY_WRITE | ENTRY_USER;
        }
        table = table_entry(table, index);
        if (table == NULL) {
            return false;
        }
    }

    size_t leaf_index = (virtual_address >> 12) & 0x1ffu;
    if ((table[leaf_index] & ENTRY_PRESENT) != 0) {
        return false;
    }

    uint64_t data_physical;
    if (memory_alloc_page(&data_physical) == NULL) {
        return false;
    }
    uint64_t entry_flags = ENTRY_PRESENT | ENTRY_USER;
    if ((flags & ADDRESS_SPACE_WRITE) != 0) {
        entry_flags |= ENTRY_WRITE;
    }
    if ((flags & ADDRESS_SPACE_EXECUTE) == 0) {
        entry_flags |= ENTRY_NO_EXECUTE;
    }
    table[leaf_index] = data_physical | entry_flags;
    if (physical_address != NULL) {
        *physical_address = data_physical;
    }
    return true;
}

static bool page_is_user_accessible(const struct address_space *space,
                                    uintptr_t virtual_address, bool write)
{
    if (space == NULL || space->root_physical == 0 ||
        (uint64_t)virtual_address >= USER_ADDRESS_LIMIT) {
        return false;
    }

    uint64_t *table = memory_phys_to_virt(space->root_physical);
    if (table == NULL) {
        return false;
    }
    const size_t indices[4] = {
        (virtual_address >> 39) & 0x1ffu,
        (virtual_address >> 30) & 0x1ffu,
        (virtual_address >> 21) & 0x1ffu,
        (virtual_address >> 12) & 0x1ffu
    };
    for (size_t level = 0; level < 3; ++level) {
        uint64_t entry = table[indices[level]];
        if ((entry & (ENTRY_PRESENT | ENTRY_USER)) !=
            (ENTRY_PRESENT | ENTRY_USER) || (entry & ENTRY_LARGE) != 0) {
            return false;
        }
        if (write && (entry & ENTRY_WRITE) == 0) {
            return false;
        }
        table = memory_phys_to_virt(entry & ~PAGE_MASK);
        if (table == NULL) {
            return false;
        }
    }

    uint64_t leaf = table[indices[3]];
    return (leaf & (ENTRY_PRESENT | ENTRY_USER)) ==
               (ENTRY_PRESENT | ENTRY_USER) &&
           (!write || (leaf & ENTRY_WRITE) != 0);
}

bool address_space_page_physical(const struct address_space *space,
                                 uintptr_t virtual_address,
                                 uint64_t *physical_address)
{
    if (space == NULL || physical_address == NULL ||
        (virtual_address & PAGE_MASK) != 0 ||
        !page_is_user_accessible(space, virtual_address, false)) {
        return false;
    }

    uint64_t *table = memory_phys_to_virt(space->root_physical);
    if (table == NULL) {
        return false;
    }
    const size_t indices[4] = {
        (virtual_address >> 39) & 0x1ffu,
        (virtual_address >> 30) & 0x1ffu,
        (virtual_address >> 21) & 0x1ffu,
        (virtual_address >> 12) & 0x1ffu
    };
    for (size_t level = 0; level < 3; ++level) {
        table = table_entry(table, indices[level]);
        if (table == NULL) {
            return false;
        }
    }
    uint64_t leaf = table[indices[3]];
    if ((leaf & ENTRY_PRESENT) == 0) {
        return false;
    }
    *physical_address = leaf & ~PAGE_MASK & ~ENTRY_NO_EXECUTE;
    return true;
}

bool address_space_user_range_valid(const struct address_space *space,
                                    uintptr_t address, size_t size,
                                    bool write)
{
    if (size == 0) {
        return true;
    }
    if (address < PAGE_SIZE || (uint64_t)address >= USER_ADDRESS_LIMIT ||
        size - 1 > UINTPTR_MAX - address) {
        return false;
    }
    uintptr_t last = address + size - 1;
    if ((uint64_t)last >= USER_ADDRESS_LIMIT) {
        return false;
    }

    uintptr_t page = address & ~(uintptr_t)PAGE_MASK;
    uintptr_t last_page = last & ~(uintptr_t)PAGE_MASK;
    for (;;) {
        if (!page_is_user_accessible(space, page, write)) {
            return false;
        }
        if (page == last_page) {
            return true;
        }
        if (page > UINTPTR_MAX - PAGE_SIZE) {
            return false;
        }
        page += PAGE_SIZE;
    }
}

bool address_space_copy_from_user(const struct address_space *space,
                                  void *destination, uintptr_t source,
                                  size_t size)
{
    if ((destination == NULL && size != 0) ||
        !address_space_user_range_valid(space, source, size, false)) {
        return false;
    }
    uint8_t *output = destination;
    const uint8_t *input = (const uint8_t *)source;
    for (size_t index = 0; index < size; ++index) {
        output[index] = input[index];
    }
    return true;
}

bool address_space_copy_to_user(const struct address_space *space,
                                uintptr_t destination, const void *source,
                                size_t size)
{
    if ((source == NULL && size != 0) ||
        !address_space_user_range_valid(space, destination, size, true)) {
        return false;
    }
    uint8_t *output = (uint8_t *)destination;
    const uint8_t *input = source;
    for (size_t index = 0; index < size; ++index) {
        output[index] = input[index];
    }
    return true;
}

void address_space_activate(uint64_t root_physical)
{
    if (root_physical == 0) {
        root_physical = kernel_root;
    }
    if (root_physical == 0 || root_physical == read_cr3()) {
        return;
    }
    __asm__ volatile ("mov %0, %%cr3" : : "r"(root_physical) : "memory");
}

bool address_space_init(void)
{
    kernel_root = read_cr3();
    return kernel_root != 0;
}
