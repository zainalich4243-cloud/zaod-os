#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "framebuffer.h"

int main(void)
{
    uint32_t pixels[80 * 60] = {0};
    struct limine_framebuffer buffer = {
        .address = pixels,
        .width = 80,
        .height = 60,
        .pitch = 80 * sizeof(uint32_t),
        .bpp = 32,
        .memory_model = LIMINE_FRAMEBUFFER_RGB,
        .red_mask_size = 8,
        .red_mask_shift = 16,
        .green_mask_size = 8,
        .green_mask_shift = 8,
        .blue_mask_size = 8,
        .blue_mask_shift = 0
    };
    assert(framebuffer_init(&buffer));
    assert(framebuffer_ready());

    framebuffer_pixel(2, 3, 0x123456);
    assert(pixels[3 * 80 + 2] == 0x123456);
    framebuffer_pixel(80, 3, 0xffffff);
    assert(pixels[3 * 80 + 2] == 0x123456);

    framebuffer_rect(78, 58, 8, 8, 0xaabbcc);
    assert(pixels[58 * 80 + 78] == 0xaabbcc);
    assert(pixels[59 * 80 + 79] == 0xaabbcc);

    framebuffer_text(0, 0, "ZAOD 123", 0xffffff, 1);
    framebuffer_draw_onboarding();
    assert(pixels[0] != 0);
    framebuffer_draw_shell(0, 0);
    uint32_t shell_background = pixels[0];
    assert(shell_background != 0);
    framebuffer_draw_shell(4, 0);
    assert(pixels[0] == shell_background);

    buffer.bpp = 24;
    assert(!framebuffer_init(&buffer));
    assert(!framebuffer_ready());
    puts("kernel framebuffer tests passed");
    return 0;
}
