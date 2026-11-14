#ifndef ZAOD_FRAMEBUFFER_H
#define ZAOD_FRAMEBUFFER_H

#include <stdbool.h>
#include <stdint.h>

#include <limine.h>

bool framebuffer_init(struct limine_framebuffer *framebuffer);
void framebuffer_pixel(uint64_t x, uint64_t y, uint32_t color);
void framebuffer_rect(uint64_t x, uint64_t y,
                      uint64_t width, uint64_t height, uint32_t color);
void framebuffer_text(uint64_t x, uint64_t y, const char *text,
                      uint32_t color, uint8_t scale);
void framebuffer_draw_onboarding(void);
void framebuffer_draw_onboarding_state(uint8_t language, uint8_t pin_length);
void framebuffer_draw_shell(uint8_t selection, uint8_t status);
bool framebuffer_ready(void);

#endif
