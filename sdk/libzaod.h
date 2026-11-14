#ifndef LIBZAOD_H
#define LIBZAOD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zaod_open_flags {
    ZAOD_OPEN_READ = 0x1u,
    ZAOD_OPEN_WRITE = 0x2u,
    ZAOD_OPEN_CREATE = 0x4u,
    ZAOD_OPEN_TRUNCATE = 0x8u
};

enum zaod_permission {
    ZAOD_PERMISSION_CAMERA = 0,
    ZAOD_PERMISSION_MICROPHONE = 1,
    ZAOD_PERMISSION_STORAGE = 2,
    ZAOD_PERMISSION_NOTIFICATIONS = 3,
    ZAOD_PERMISSION_NETWORK = 4
};

enum zaod_input_type {
    ZAOD_INPUT_KEY = 0,
    ZAOD_INPUT_MOUSE = 1
};

struct zaod_input_event {
    uint32_t type;
    char key;
    uint8_t reserved0;
    int16_t mouse_dx;
    int16_t mouse_dy;
    uint8_t mouse_buttons;
    uint8_t reserved1;
};

int64_t zaod_open(const char *path, uint32_t flags);
int64_t zaod_read(int64_t descriptor, void *buffer, size_t size);
int64_t zaod_write(int64_t descriptor, const void *buffer, size_t size);
int64_t zaod_exec(const char *path);
int64_t zaod_request_perm(enum zaod_permission permission);
int64_t zaod_input_read(struct zaod_input_event *event);
int64_t zaod_ui_draw_onboarding(uint8_t language, uint8_t pin_length);
int64_t zaod_exit(void);

#ifdef __cplusplus
}
#endif

#endif
