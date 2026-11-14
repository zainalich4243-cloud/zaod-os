#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "persistent_fs.h"

#define TEST_SECTORS 65553u

static uint8_t *disk;

uint64_t block_sector_count(void)
{
    return TEST_SECTORS;
}

bool block_read_sector(uint64_t lba, uint8_t sector[BLOCK_SECTOR_SIZE])
{
    if (lba >= TEST_SECTORS || sector == NULL) {
        return false;
    }
    memcpy(sector, disk + lba * BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
    return true;
}

bool block_write_sector(uint64_t lba,
                        const uint8_t sector[BLOCK_SECTOR_SIZE])
{
    if (lba >= TEST_SECTORS || sector == NULL) {
        return false;
    }
    memcpy(disk + lba * BLOCK_SECTOR_SIZE, sector, BLOCK_SECTOR_SIZE);
    return true;
}

int main(void)
{
    disk = calloc(TEST_SECTORS, BLOCK_SECTOR_SIZE);
    assert(disk != NULL);
    assert(persistent_fs_format());
    assert(persistent_fs_mount());
    assert(persistent_fs_path_allowed("/home/user/settings"));
    assert(persistent_fs_path_allowed("/opt/zaod/apps/demo/app"));
    assert(!persistent_fs_path_allowed("/home/../etc/passwd"));
    assert(!persistent_fs_path_allowed("/etc/passwd"));

    size_t slot;
    size_t file_size;
    assert(persistent_fs_open("/home/user/settings", true, false,
                              &slot, &file_size) == 0);
    assert(file_size == 0);
    const char contents[] = "persisted";
    assert(persistent_fs_write(slot, 0, contents, sizeof(contents)) ==
           (int64_t)sizeof(contents));
    assert(persistent_fs_size(slot, &file_size));
    assert(file_size == sizeof(contents));

    assert(persistent_fs_mount());
    size_t reopened_slot;
    assert(persistent_fs_open("/home/user/settings", false, false,
                              &reopened_slot, &file_size) == 0);
    assert(reopened_slot == slot);
    assert(file_size == sizeof(contents));
    char loaded[sizeof(contents)] = {0};
    assert(persistent_fs_read(slot, 0, loaded, sizeof(loaded)) ==
           (int64_t)sizeof(loaded));
    assert(memcmp(loaded, contents, sizeof(contents)) == 0);
    assert(persistent_fs_write(slot, 0, contents,
                               PERSISTENT_FS_MAX_FILE_SIZE + 1u) < 0);

    assert(persistent_fs_open("/home/user/settings", false, true,
                              &reopened_slot, &file_size) == 0);
    assert(file_size == 0);
    assert(persistent_fs_size(slot, &file_size));
    assert(file_size == 0);

    free(disk);
    puts("kernel persistent filesystem tests passed");
    return 0;
}
