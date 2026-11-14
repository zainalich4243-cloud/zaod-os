#ifndef ZAOD_INPUT_H
#define ZAOD_INPUT_H

#include <stdbool.h>
#include <stdint.h>

enum input_event_type {
    INPUT_EVENT_KEY,
    INPUT_EVENT_MOUSE
};

struct input_event {
    enum input_event_type type;
    char key;
    int16_t mouse_dx;
    int16_t mouse_dy;
    uint8_t mouse_buttons;
};

bool input_init(void);
void input_keyboard_irq(void);
void input_mouse_irq(void);
bool input_event_pop(struct input_event *event);

#endif
