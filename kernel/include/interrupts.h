#ifndef ZAOD_INTERRUPTS_H
#define ZAOD_INTERRUPTS_H

#include <stdbool.h>

#include "task.h"

void interrupts_init(void);
struct interrupt_frame *interrupt_dispatch(struct interrupt_frame *frame);
uint64_t timer_ticks(void);
bool mouse_irq_available(void);

#endif
