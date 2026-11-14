#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "input.h"

#define EVENT_CAPACITY 64
#define PS2_STATUS 0x64
#define PS2_DATA 0x60

static struct input_event events[EVENT_CAPACITY];
static size_t event_head;
static size_t event_tail;
static bool shift_down;
static uint8_t mouse_packet[3];
static size_t mouse_packet_index;

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

static bool wait_for_input_clear(void)
{
    for (size_t attempt = 0; attempt < 100000; ++attempt) {
        if ((inb(PS2_STATUS) & 0x02) == 0) {
            return true;
        }
        __asm__ volatile ("pause");
    }
    return false;
}

static bool wait_for_output_full(void)
{
    for (size_t attempt = 0; attempt < 100000; ++attempt) {
        if ((inb(PS2_STATUS) & 0x01) != 0) {
            return true;
        }
        __asm__ volatile ("pause");
    }
    return false;
}

static bool mouse_command(uint8_t command)
{
    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_STATUS, 0xd4);
    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_DATA, command);
    return wait_for_output_full() && inb(PS2_DATA) == 0xfa;
}

static void enqueue(struct input_event event)
{
    size_t next = (event_head + 1) % EVENT_CAPACITY;
    if (next == event_tail) {
        return;
    }
    events[event_head] = event;
    event_head = next;
}

static char translate_scancode(uint8_t code)
{
    static const char normal[128] = {
        [0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
        [0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
        [0x0a] = '9', [0x0b] = '0', [0x0c] = '-', [0x0d] = '=',
        [0x0e] = '\b', [0x0f] = '\t',
        [0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r',
        [0x14] = 't', [0x15] = 'y', [0x16] = 'u', [0x17] = 'i',
        [0x18] = 'o', [0x19] = 'p', [0x1a] = '[', [0x1b] = ']',
        [0x1c] = '\n', [0x1e] = 'a', [0x1f] = 's', [0x20] = 'd',
        [0x21] = 'f', [0x22] = 'g', [0x23] = 'h', [0x24] = 'j',
        [0x25] = 'k', [0x26] = 'l', [0x27] = ';', [0x28] = '\'',
        [0x29] = '`', [0x2b] = '\\', [0x2c] = 'z', [0x2d] = 'x',
        [0x2e] = 'c', [0x2f] = 'v', [0x30] = 'b', [0x31] = 'n',
        [0x32] = 'm', [0x33] = ',', [0x34] = '.', [0x35] = '/',
        [0x39] = ' '
    };
    static const char shifted_digits[] = "!@#$%^&*()";
    if (code >= 0x02 && code <= 0x0b && shift_down) {
        return shifted_digits[code - 0x02];
    }
    char value = normal[code];
    if (shift_down && value >= 'a' && value <= 'z') {
        value = (char)(value - 'a' + 'A');
    }
    return value;
}

bool input_init(void)
{
    event_head = 0;
    event_tail = 0;
    shift_down = false;
    mouse_packet_index = 0;

    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_STATUS, 0xa8);
    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_STATUS, 0x20);
    if (!wait_for_output_full()) {
        return false;
    }
    uint8_t command_byte = inb(PS2_DATA);
    command_byte = (uint8_t)((command_byte | 0x02) & ~0x20u);
    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_STATUS, 0x60);
    if (!wait_for_input_clear()) {
        return false;
    }
    outb(PS2_DATA, command_byte);

    return mouse_command(0xf6) && mouse_command(0xf4);
}

void input_keyboard_irq(void)
{
    uint8_t scancode = inb(PS2_DATA);
    if (scancode == 0x2a || scancode == 0x36) {
        shift_down = true;
        return;
    }
    if (scancode == 0xaa || scancode == 0xb6) {
        shift_down = false;
        return;
    }
    if ((scancode & 0x80) != 0) {
        return;
    }
    char key = translate_scancode(scancode);
    if (key != '\0') {
        enqueue((struct input_event) {
            .type = INPUT_EVENT_KEY,
            .key = key
        });
    }
}

void input_mouse_irq(void)
{
    uint8_t value = inb(PS2_DATA);
    if (mouse_packet_index == 0 && (value & 0x08) == 0) {
        return;
    }
    mouse_packet[mouse_packet_index++] = value;
    if (mouse_packet_index == sizeof(mouse_packet)) {
        enqueue((struct input_event) {
            .type = INPUT_EVENT_MOUSE,
            .mouse_dx = (int8_t)mouse_packet[1],
            .mouse_dy = (int16_t)-(int8_t)mouse_packet[2],
            .mouse_buttons = mouse_packet[0] & 0x07
        });
        mouse_packet_index = 0;
    }
}

bool input_event_pop(struct input_event *event)
{
    if (event == NULL || event_tail == event_head) {
        return false;
    }
    *event = events[event_tail];
    event_tail = (event_tail + 1) % EVENT_CAPACITY;
    return true;
}
