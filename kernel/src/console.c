#include <stddef.h>
#include <stdint.h>

#include "console.h"

#define COM1 0x3f8

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

void console_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xc7);
    outb(COM1 + 4, 0x0b);
}

static void console_putc(char value)
{
    for (size_t attempt = 0; attempt < 100000; ++attempt) {
        if ((inb(COM1 + 5) & 0x20) != 0) {
            break;
        }
    }
    outb(COM1, (uint8_t)value);
}

static char console_getc(void)
{
    while ((inb(COM1 + 5) & 0x01) == 0) {
        __asm__ volatile ("pause");
    }
    return (char)inb(COM1);
}

void console_write(const char *text)
{
    if (text == NULL) {
        return;
    }

    while (*text != '\0') {
        if (*text == '\n') {
            console_putc('\r');
        }
        console_putc(*text++);
    }
}

void console_write_u64(uint64_t value)
{
    char digits[20];
    size_t count = 0;

    if (value == 0) {
        console_putc('0');
        return;
    }

    while (value != 0) {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    }
    while (count != 0) {
        console_putc(digits[--count]);
    }
}

void console_write_hex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";

    console_write("0x");
    for (int shift = 60; shift >= 0; shift -= 4) {
        console_putc(digits[(value >> shift) & 0xf]);
    }
}

size_t console_readline(char *buffer, size_t capacity)
{
    if (buffer == NULL || capacity == 0) {
        return 0;
    }

    size_t length = 0;
    for (;;) {
        char value = console_getc();
        if (value == '\r' || value == '\n') {
            console_write("\n");
            break;
        }
        if (value == '\b' || value == 0x7f) {
            if (length != 0) {
                --length;
                console_write("\b \b");
            }
            continue;
        }
        if (value >= 0x20 && value <= 0x7e && length + 1 < capacity) {
            buffer[length++] = value;
            console_putc(value);
        }
    }

    buffer[length] = '\0';
    return length;
}
