#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "memory.h"

#define PAGE_SIZE 4096
#define LOW_MEMORY_LIMIT 0x100000

static struct limine_memmap_response *memory_map;
static uint64_t hhdm_offset;
static uint64_t region_index;
static uint64_t region_cursor;
static uint64_t cursor_region_index = UINT64_MAX;
static uint64_t usable_memory;
static uint64_t allocated_pages;

bool memory_init(struct limine_memmap_response *map,
                 struct limine_hhdm_response *hhdm)
{
    if (map == NULL || hhdm == NULL || map->entries == NULL) {
        return false;
    }

    memory_map = map;
    hhdm_offset = hhdm->offset;
    region_index = 0;

    usable_memory = 0;
    allocated_pages = 0;
    for (uint64_t i = 0; i < map->entry_count; ++i) {
        struct limine_memmap_entry *entry = map->entries[i];
        if (entry == NULL || entry->type != LIMINE_MEMMAP_USABLE ||
            entry->length > UINT64_MAX - entry->base) {
            continue;
        }

        if (entry->length <= UINT64_MAX - usable_memory) {
            usable_memory += entry->length;
        }
    }

    console_write("Usable physical memory: ");
    console_write_u64(usable_memory / (1024 * 1024));
    console_write(" MiB\n");
    console_write("HHDM offset: ");
    console_write_hex(hhdm_offset);
    console_write("\n");
    return true;
}

void *memory_alloc_page(uint64_t *physical_address)
{
    if (memory_map == NULL) {
        return NULL;
    }

    while (region_index < memory_map->entry_count) {
        struct limine_memmap_entry *entry = memory_map->entries[region_index];
        if (entry == NULL || entry->type != LIMINE_MEMMAP_USABLE ||
            entry->length > UINT64_MAX - entry->base) {
            ++region_index;
            continue;
        }

        uint64_t start = entry->base;
        if (start < LOW_MEMORY_LIMIT) {
            start = LOW_MEMORY_LIMIT;
        }
        if (start > UINT64_MAX - (PAGE_SIZE - 1)) {
            ++region_index;
            continue;
        }
        start = (start + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t end = entry->base + entry->length;

        if (cursor_region_index != region_index) {
            region_cursor = start;
            cursor_region_index = region_index;
        }
        if (region_cursor < start) {
            region_cursor = start;
        }

        if (region_cursor > end || end - region_cursor < PAGE_SIZE) {
            ++region_index;
            continue;
        }
        if (region_cursor > UINT64_MAX - PAGE_SIZE ||
            hhdm_offset > UINT64_MAX - region_cursor) {
            ++region_index;
            continue;
        }

        uint64_t allocated_address = region_cursor;
        region_cursor += PAGE_SIZE;
        if (physical_address != NULL) {
            *physical_address = allocated_address;
        }

        void *page = (void *)(uintptr_t)(hhdm_offset + allocated_address);
        volatile uint64_t *words = page;
        for (size_t i = 0; i < PAGE_SIZE / sizeof(*words); ++i) {
            words[i] = 0;
        }
        ++allocated_pages;
        return page;
    }

    return NULL;
}

void *memory_phys_to_virt(uint64_t physical_address)
{
    if (hhdm_offset > UINT64_MAX - physical_address) {
        return NULL;
    }
    return (void *)(uintptr_t)(hhdm_offset + physical_address);
}

uint64_t memory_usable_bytes(void)
{
    return usable_memory;
}

uint64_t memory_allocated_pages(void)
{
    return allocated_pages;
}
