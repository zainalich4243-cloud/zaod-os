#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "framebuffer.h"

#define FRAMEBUFFER_MAX_DIMENSION 8192

static struct limine_framebuffer *active_framebuffer;

static const uint8_t font[36][5] = {
    {0x7e,0x11,0x11,0x11,0x7e}, {0x7f,0x49,0x49,0x49,0x36},
    {0x3e,0x41,0x41,0x41,0x22}, {0x7f,0x41,0x41,0x22,0x1c},
    {0x7f,0x49,0x49,0x49,0x41}, {0x7f,0x09,0x09,0x09,0x01},
    {0x3e,0x41,0x49,0x49,0x7a}, {0x7f,0x08,0x08,0x08,0x7f},
    {0x00,0x41,0x7f,0x41,0x00}, {0x20,0x40,0x41,0x3f,0x01},
    {0x7f,0x08,0x14,0x22,0x41}, {0x7f,0x40,0x40,0x40,0x40},
    {0x7f,0x02,0x0c,0x02,0x7f}, {0x7f,0x04,0x08,0x10,0x7f},
    {0x3e,0x41,0x41,0x41,0x3e}, {0x7f,0x09,0x09,0x09,0x06},
    {0x3e,0x41,0x51,0x21,0x5e}, {0x7f,0x09,0x19,0x29,0x46},
    {0x46,0x49,0x49,0x49,0x31}, {0x01,0x01,0x7f,0x01,0x01},
    {0x3f,0x40,0x40,0x40,0x3f}, {0x1f,0x20,0x40,0x20,0x1f},
    {0x3f,0x40,0x38,0x40,0x3f}, {0x63,0x14,0x08,0x14,0x63},
    {0x07,0x08,0x70,0x08,0x07}, {0x61,0x51,0x49,0x45,0x43},
    {0x3e,0x51,0x49,0x45,0x3e}, {0x00,0x42,0x7f,0x40,0x00},
    {0x42,0x61,0x51,0x49,0x46}, {0x21,0x41,0x45,0x4b,0x31},
    {0x18,0x14,0x12,0x7f,0x10}, {0x27,0x45,0x45,0x45,0x39},
    {0x3c,0x4a,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36}, {0x06,0x49,0x49,0x29,0x1e}
};

static uint32_t color_component(uint32_t color, uint8_t size, uint8_t shift)
{
    uint32_t component = (color >> shift) & 0xffu;
    uint32_t maximum = size == 0 ? 0 : (1u << size) - 1u;
    if (size >= 8) {
        return component << shift;
    }
    return ((component * maximum + 127u) / 255u) << shift;
}

bool framebuffer_init(struct limine_framebuffer *framebuffer)
{
    active_framebuffer = NULL;
    if (framebuffer == NULL || framebuffer->address == NULL ||
        framebuffer->width == 0 || framebuffer->height == 0 ||
        framebuffer->width > FRAMEBUFFER_MAX_DIMENSION ||
        framebuffer->height > FRAMEBUFFER_MAX_DIMENSION ||
        framebuffer->bpp != 32 ||
        framebuffer->memory_model != LIMINE_FRAMEBUFFER_RGB ||
        framebuffer->red_mask_size == 0 ||
        framebuffer->green_mask_size == 0 ||
        framebuffer->blue_mask_size == 0 ||
        framebuffer->red_mask_shift + framebuffer->red_mask_size > 32 ||
        framebuffer->green_mask_shift + framebuffer->green_mask_size > 32 ||
        framebuffer->blue_mask_shift + framebuffer->blue_mask_size > 32 ||
        framebuffer->pitch < framebuffer->width * sizeof(uint32_t) ||
        framebuffer->height > UINT64_MAX / framebuffer->pitch) {
        return false;
    }
    active_framebuffer = framebuffer;
    return true;
}

bool framebuffer_ready(void)
{
    return active_framebuffer != NULL;
}

void framebuffer_pixel(uint64_t x, uint64_t y, uint32_t color)
{
    if (active_framebuffer == NULL || x >= active_framebuffer->width ||
        y >= active_framebuffer->height) {
        return;
    }
    uint32_t packed =
        color_component(color, active_framebuffer->red_mask_size,
                        active_framebuffer->red_mask_shift) |
        color_component(color, active_framebuffer->green_mask_size,
                        active_framebuffer->green_mask_shift) |
        color_component(color, active_framebuffer->blue_mask_size,
                        active_framebuffer->blue_mask_shift);
    volatile uint32_t *row = (volatile uint32_t *)(
        (uintptr_t)active_framebuffer->address + y * active_framebuffer->pitch);
    row[x] = packed;
}

void framebuffer_rect(uint64_t x, uint64_t y,
                      uint64_t width, uint64_t height, uint32_t color)
{
    if (active_framebuffer == NULL || x >= active_framebuffer->width ||
        y >= active_framebuffer->height) {
        return;
    }
    uint64_t max_width = active_framebuffer->width - x;
    uint64_t max_height = active_framebuffer->height - y;
    if (width > max_width) {
        width = max_width;
    }
    if (height > max_height) {
        height = max_height;
    }
    for (uint64_t row = 0; row < height; ++row) {
        for (uint64_t column = 0; column < width; ++column) {
            framebuffer_pixel(x + column, y + row, color);
        }
    }
}

static const uint8_t *glyph_for(char value)
{
    if (value >= 'a' && value <= 'z') {
        value = (char)(value - 'a' + 'A');
    }
    if (value >= 'A' && value <= 'Z') {
        return font[(size_t)(value - 'A')];
    }
    if (value >= '0' && value <= '9') {
        return font[26 + (size_t)(value - '0')];
    }
    static const uint8_t colon[5] = {0,0x36,0x36,0,0};
    static const uint8_t hyphen[5] = {0x08,0x08,0x08,0x08,0x08};
    static const uint8_t unknown[5] = {0x02,0x01,0x51,0x09,0x06};
    if (value == ':') {
        return colon;
    }
    if (value == '-') {
        return hyphen;
    }
    return unknown;
}

void framebuffer_text(uint64_t x, uint64_t y, const char *text,
                      uint32_t color, uint8_t scale)
{
    if (active_framebuffer == NULL || text == NULL ||
        scale == 0 || scale > 8) {
        return;
    }
    uint64_t origin_x = x;
    for (size_t index = 0; text[index] != '\0'; ++index) {
        if (text[index] == '\n') {
            y += 9u * scale;
            x = origin_x;
            continue;
        }
        if (text[index] != ' ') {
            const uint8_t *glyph = glyph_for(text[index]);
            for (size_t column = 0; column < 5; ++column) {
                for (size_t row = 0; row < 7; ++row) {
                    if ((glyph[column] & (1u << row)) != 0) {
                        framebuffer_rect(
                            x + column * scale,
                            y + row * scale,
                            scale, scale, color);
                    }
                }
            }
        }
        x += 6u * scale;
    }
}

void framebuffer_draw_onboarding(void)
{
    framebuffer_draw_onboarding_state(0, 0);
}

void framebuffer_draw_onboarding_state(uint8_t language, uint8_t pin_length)
{
    if (active_framebuffer == NULL) {
        return;
    }
    framebuffer_rect(0, 0, active_framebuffer->width,
                    active_framebuffer->height, 0x101827);
    uint64_t panel_width = active_framebuffer->width <= 32
        ? active_framebuffer->width
        : active_framebuffer->width < 720
            ? active_framebuffer->width - 32
            : 688;
    uint64_t panel_height = 260;
    uint64_t panel_x = (active_framebuffer->width - panel_width) / 2;
    uint64_t panel_y = active_framebuffer->height > panel_height
        ? (active_framebuffer->height - panel_height) / 2
        : 8;
    framebuffer_rect(panel_x, panel_y, panel_width, panel_height, 0x1c293b);
    framebuffer_text(panel_x + 28, panel_y + 26,
                     "ZAOD OS ONBOARDING", 0xf1f5f9, 3);
    framebuffer_text(panel_x + 28, panel_y + 94,
                     language == 2 ? "LANGUAGE: URDU" : "LANGUAGE: ENGLISH",
                     0xcbd5e1, 2);
    framebuffer_text(panel_x + 28, panel_y + 142,
                     "LOCAL PIN SETUP", 0xcbd5e1, 2);
    framebuffer_text(panel_x + 28, panel_y + 166, "PIN:", 0xcbd5e1, 1);
    if (pin_length > 8) {
        pin_length = 8;
    }
    for (uint8_t i = 0; i < pin_length; ++i) {
        framebuffer_rect(panel_x + 64 + (uint64_t)i * 12,
                         panel_y + 167, 6, 6, 0x38bdf8);
    }
    framebuffer_rect(panel_x + 28, panel_y + 190,
                    panel_width > 56 ? panel_width - 56 : 0, 2, 0x38bdf8);
}

void framebuffer_draw_shell(uint8_t selection, uint8_t status)
{
    static const char *const labels[4] = {
        "1 FILES", "2 NOTES", "3 TERMINAL", "4 SETTINGS"
    };
    static const char *const statuses[5] = {
        "READY", "PACKAGE MISSING", "LAUNCH DENIED",
        "APP STARTED", "SETTINGS NOT BUILT"
    };
    if (active_framebuffer == NULL || selection > 3 || status > 4) {
        return;
    }

    framebuffer_rect(0, 0, active_framebuffer->width,
                     active_framebuffer->height, 0x101827);
    uint64_t panel_width = active_framebuffer->width <= 32
        ? active_framebuffer->width
        : active_framebuffer->width < 720
            ? active_framebuffer->width - 32
            : 688;
    uint64_t panel_height = 300;
    uint64_t panel_x = (active_framebuffer->width - panel_width) / 2;
    uint64_t panel_y = active_framebuffer->height > panel_height
        ? (active_framebuffer->height - panel_height) / 2
        : 8;
    framebuffer_rect(panel_x, panel_y, panel_width, panel_height, 0x1c293b);
    framebuffer_text(panel_x + 24, panel_y + 20,
                     "ZAOD OS SHELL", 0xf1f5f9, 3);
    framebuffer_text(panel_x + 24, panel_y + 64,
                     "SIGNED APP LAUNCHER", 0x94a3b8, 1);
    framebuffer_rect(panel_x + 24, panel_y + 92,
                     panel_width > 48 ? panel_width - 48 : 0,
                     1, 0x475569);
    for (uint8_t index = 0; index < 4; ++index) {
        uint64_t row_y = panel_y + 112 + (uint64_t)index * 34;
        uint32_t background = index == selection
            ? 0x075985
            : 0x27364b;
        framebuffer_rect(panel_x + 24, row_y,
                         panel_width > 48 ? panel_width - 48 : 0,
                         26, background);
        framebuffer_text(panel_x + 36, row_y + 9,
                         labels[index], 0xf1f5f9, 1);
    }
    framebuffer_text(panel_x + 24, panel_y + 256,
                     "STATUS:", 0x94a3b8, 1);
    framebuffer_text(panel_x + 84, panel_y + 256,
                     statuses[status], 0x38bdf8, 1);
    framebuffer_text(panel_x + 24, panel_y + 278,
                     "W S SELECT - ENTER OPEN - B HOME", 0x94a3b8, 1);
}
