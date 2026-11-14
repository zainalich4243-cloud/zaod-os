#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"

#define ATA_DATA 0x1f0u
#define ATA_ERROR 0x1f1u
#define ATA_SECTOR_COUNT 0x1f2u
#define ATA_LBA_LOW 0x1f3u
#define ATA_LBA_MID 0x1f4u
#define ATA_LBA_HIGH 0x1f5u
#define ATA_DRIVE 0x1f6u
#define ATA_STATUS 0x1f7u
#define ATA_COMMAND 0x1f7u
#define ATA_CONTROL 0x3f6u
#define ATA_STATUS_ERR 0x01u
#define ATA_STATUS_DRQ 0x08u
#define ATA_STATUS_DF 0x20u
#define ATA_STATUS_BSY 0x80u
#define ATA_CMD_IDENTIFY 0xecu
#define ATA_CMD_READ 0x20u
#define ATA_CMD_WRITE 0x30u
#define ATA_CMD_FLUSH 0xe7u
#define ATA_LBA28_LIMIT 0x10000000ull
#define ATA_POLL_LIMIT 1000000u

static uint64_t disk_sectors;

static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline uint16_t inw(uint16_t port)
{
    uint16_t value;
    __asm__ volatile ("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void outw(uint16_t port, uint16_t value)
{
    __asm__ volatile ("outw %0, %1" : : "a"(value), "Nd"(port));
}

static void ata_delay_400ns(void)
{
    (void)inb(ATA_CONTROL);
    (void)inb(ATA_CONTROL);
    (void)inb(ATA_CONTROL);
    (void)inb(ATA_CONTROL);
}

static bool ata_wait(bool require_data)
{
    for (uint32_t poll = 0; poll < ATA_POLL_LIMIT; ++poll) {
        uint8_t status = inb(ATA_STATUS);
        if (status == 0) {
            return false;
        }
        if ((status & ATA_STATUS_BSY) != 0) {
            continue;
        }
        if ((status & (ATA_STATUS_ERR | ATA_STATUS_DF)) != 0) {
            (void)inb(ATA_ERROR);
            return false;
        }
        if (!require_data || (status & ATA_STATUS_DRQ) != 0) {
            return true;
        }
    }
    return false;
}

static bool ata_transfer(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE],
                         bool write)
{
    if (disk_sectors == 0 || lba >= disk_sectors ||
        lba >= ATA_LBA28_LIMIT || sector == NULL) {
        return false;
    }

    uint64_t saved_flags;
    __asm__ volatile ("pushfq; popq %0; cli"
                      : "=r"(saved_flags)
                      :
                      : "memory");
    outb(ATA_DRIVE, (uint8_t)(0xe0u | ((lba >> 24) & 0x0fu)));
    ata_delay_400ns();
    outb(ATA_SECTOR_COUNT, 1);
    outb(ATA_LBA_LOW, (uint8_t)lba);
    outb(ATA_LBA_MID, (uint8_t)(lba >> 8));
    outb(ATA_LBA_HIGH, (uint8_t)(lba >> 16));
    outb(ATA_COMMAND, write ? ATA_CMD_WRITE : ATA_CMD_READ);

    bool success = ata_wait(true);
    if (success) {
        for (size_t index = 0; index < BLOCK_SECTOR_SIZE / 2; ++index) {
            if (write) {
                uint16_t value = (uint16_t)sector[index * 2] |
                    ((uint16_t)sector[index * 2 + 1] << 8);
                outw(ATA_DATA, value);
            } else {
                uint16_t value = inw(ATA_DATA);
                sector[index * 2] = (uint8_t)value;
                sector[index * 2 + 1] = (uint8_t)(value >> 8);
            }
        }
        if (write) {
            ata_delay_400ns();
            outb(ATA_COMMAND, ATA_CMD_FLUSH);
            success = ata_wait(false);
        }
    }

    if ((saved_flags & (1ull << 9)) != 0) {
        __asm__ volatile ("sti" : : : "memory");
    }
    return success;
}

bool ata_block_init(void)
{
    disk_sectors = 0;
    outb(ATA_CONTROL, 0x02);
    outb(ATA_DRIVE, 0xa0);
    ata_delay_400ns();
    outb(ATA_SECTOR_COUNT, 0);
    outb(ATA_LBA_LOW, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, ATA_CMD_IDENTIFY);
    if (inb(ATA_STATUS) == 0 || !ata_wait(false) ||
        inb(ATA_LBA_MID) != 0 || inb(ATA_LBA_HIGH) != 0 ||
        !ata_wait(true)) {
        return false;
    }

    uint16_t identify[256];
    for (size_t index = 0; index < 256; ++index) {
        identify[index] = inw(ATA_DATA);
    }
    if ((identify[49] & (1u << 9)) == 0) {
        return false;
    }
    disk_sectors = (uint64_t)identify[60] |
                   ((uint64_t)identify[61] << 16);
    if (disk_sectors == 0 || disk_sectors > ATA_LBA28_LIMIT) {
        disk_sectors = 0;
        return false;
    }
    return true;
}

uint64_t block_sector_count(void)
{
    return disk_sectors;
}

bool block_read_sector(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE])
{
    return ata_transfer(lba, sector, false);
}

bool block_write_sector(uint64_t lba,
                        const uint8_t sector[BLOCK_SECTOR_SIZE])
{
    return ata_transfer(lba, (uint8_t *)sector, true);
}
