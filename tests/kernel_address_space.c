#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <limine.h>

#include "address_space.h"
#include "console.h"
#include "memory.h"

#define PAGE_PRESENT (1ull << 0)
#define PAGE_WRITE (1ull << 1)
#define PAGE_USER (1ull << 2)
#define PAGE_NO_EXECUTE (1ull << 63)
#define PAGE_ADDRESS_MASK (~0xfffull)

void console_write(const char *text)
{
    (void)text;
}

void console_write_u64(uint64_t value)
{
    (void)value;
}

void console_write_hex(uint64_t value)
{
    (void)value;
}

static uint64_t pml4[512] __attribute__((aligned(4096)));
static uint64_t pdpt[512] __attribute__((aligned(4096)));
static uint64_t pd[512] __attribute__((aligned(4096)));
static uint64_t pt[512] __attribute__((aligned(4096)));
static uint8_t user_page[4096] __attribute__((aligned(4096)));

int main(void)
{
    struct limine_memmap_response map = {
        .entry_count = 0,
        .entries = (struct limine_memmap_entry *[]){NULL}
    };
    struct limine_hhdm_response hhdm = {.offset = 0};
    assert(memory_init(&map, &hhdm));

    const uintptr_t mapped_va = 0x400000;
    pml4[0] = (uintptr_t)pdpt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    pdpt[0] = (uintptr_t)pd | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    pd[2] = (uintptr_t)pt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    pt[0] = (uintptr_t)user_page | PAGE_PRESENT | PAGE_WRITE |
            PAGE_USER | PAGE_NO_EXECUTE;
    struct address_space space = {.root_physical = (uintptr_t)pml4};

    assert(address_space_user_range_valid(&space, mapped_va, 16, false));
    assert(address_space_user_range_valid(&space, mapped_va, 16, true));
    assert(!address_space_user_range_valid(&space, mapped_va + 4090, 7, true));
    assert(!address_space_user_range_valid(&space, 0x500000, 1, false));
    assert(!address_space_user_range_valid(&space, 0xffff800000000000ull,
                                           1, false));

    pt[0] &= ~PAGE_WRITE;
    assert(address_space_user_range_valid(&space, mapped_va, 16, false));
    assert(!address_space_user_range_valid(&space, mapped_va, 16, true));

    uint64_t physical_address;
    assert(address_space_page_physical(&space, mapped_va,
                                       &physical_address));
    assert(physical_address == (uintptr_t)user_page);

    puts("kernel address-space permission tests passed");
    return 0;
}
