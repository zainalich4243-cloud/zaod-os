#ifndef ZAOD_MEMORY_H
#define ZAOD_MEMORY_H

#include <stdbool.h>
#include <stdint.h>

#include <limine.h>

bool memory_init(struct limine_memmap_response *map,
                 struct limine_hhdm_response *hhdm);
void *memory_alloc_page(uint64_t *physical_address);
void *memory_phys_to_virt(uint64_t physical_address);
uint64_t memory_usable_bytes(void);
uint64_t memory_allocated_pages(void);

#endif
