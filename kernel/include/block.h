#ifndef ZAOD_BLOCK_H
#define ZAOD_BLOCK_H

#include <stdbool.h>
#include <stdint.h>

#define BLOCK_SECTOR_SIZE 512u

bool ata_block_init(void);
uint64_t block_sector_count(void);
bool block_read_sector(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE]);
bool block_write_sector(uint64_t lba,
                        const uint8_t sector[BLOCK_SECTOR_SIZE]);

#endif
