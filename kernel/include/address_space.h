#ifndef ZAOD_ADDRESS_SPACE_H
#define ZAOD_ADDRESS_SPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct address_space {
    uint64_t root_physical;
};

enum address_space_flags {
    ADDRESS_SPACE_WRITE = 1u << 0,
    ADDRESS_SPACE_EXECUTE = 1u << 1
};

bool address_space_create(struct address_space *space);
bool address_space_init(void);
bool address_space_map_page(struct address_space *space,
                            uintptr_t virtual_address, uint32_t flags,
                            uint64_t *physical_address);
bool address_space_page_physical(const struct address_space *space,
                                 uintptr_t virtual_address,
                                 uint64_t *physical_address);
bool address_space_user_range_valid(const struct address_space *space,
                                    uintptr_t address, size_t size,
                                    bool write);
bool address_space_copy_from_user(const struct address_space *space,
                                  void *destination, uintptr_t source,
                                  size_t size);
bool address_space_copy_to_user(const struct address_space *space,
                                uintptr_t destination, const void *source,
                                size_t size);
uint64_t address_space_kernel_root(void);
void address_space_activate(uint64_t root_physical);

#endif
