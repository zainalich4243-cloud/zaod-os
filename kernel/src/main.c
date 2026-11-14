#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <limine.h>

#include "address_space.h"
#include "block.h"
#include "console.h"
#include "elf.h"
#include "framebuffer.h"
#include "gdt.h"
#include "input.h"
#include "interrupts.h"
#include "memory.h"
#include "permissions.h"
#include "persistent_fs.h"
#include "security.h"
#include "syscall.h"
#include "task.h"
#include "vfs.h"

__attribute__((used, section(".limine_requests_start_marker")))
static volatile uint64_t requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests")))
static volatile uint64_t base_revision[] = LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests")))
static volatile struct limine_bootloader_info_request bootloader_request = {
    .id = LIMINE_BOOTLOADER_INFO_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_executable_cmdline_request cmdline_request = {
    .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_hhdm_request hhdm_request = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_module_request module_request = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_framebuffer_request framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;

static __attribute__((noreturn)) void halt_forever(void)
{
    __asm__ volatile ("cli");
    for (;;) {
        __asm__ volatile ("hlt");
    }
}

static bool text_equals(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static enum permission_choice console_permission_prompt(
    const char *app_id,
    enum permission_resource resource,
    uint32_t choices,
    void *context)
{
    (void)context;
    char answer[8];
    console_write("\nPermission request from ");
    console_write(app_id);
    console_write(" for ");
    switch (resource) {
    case PERMISSION_CAMERA:
        console_write("camera");
        break;
    case PERMISSION_MICROPHONE:
        console_write("microphone");
        break;
    case PERMISSION_STORAGE:
        console_write("storage");
        break;
    case PERMISSION_NOTIFICATIONS:
        console_write("notifications");
        break;
    case PERMISSION_NETWORK:
        console_write("network");
        break;
    case PERMISSION_RESOURCE_COUNT:
        return PERMISSION_CHOICE_DENY;
    }
    console_write("\n[d]eny");
    if ((choices & PERMISSION_PROMPT_ONLY_THIS_TIME) != 0) {
        console_write(" [1]only this time");
    }
    if ((choices & PERMISSION_PROMPT_WHILE_USING) != 0) {
        console_write(" [2]while using");
    }
    console_write(": ");
    console_readline(answer, sizeof(answer));

    if (text_equals(answer, "1") &&
        (choices & PERMISSION_PROMPT_ONLY_THIS_TIME) != 0) {
        return PERMISSION_CHOICE_ONLY_THIS_TIME;
    }
    if (text_equals(answer, "2") &&
        (choices & PERMISSION_PROMPT_WHILE_USING) != 0) {
        return PERMISSION_CHOICE_WHILE_USING;
    }
    return PERMISSION_CHOICE_DENY;
}

static void print_cpu_vendor(void)
{
    uint32_t eax = 0;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    char vendor[13];

    eax = 0;
    ecx = 0;
    __asm__ volatile ("cpuid"
                      : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));

    for (size_t i = 0; i < 4; ++i) {
        vendor[i] = (char)(ebx >> (i * 8));
        vendor[i + 4] = (char)(edx >> (i * 8));
        vendor[i + 8] = (char)(ecx >> (i * 8));
    }
    vendor[12] = '\0';
    console_write("CPU vendor: ");
    console_write(vendor);
    console_write("\n");
}

static void print_memory_info(void)
{
    console_write("Usable RAM: ");
    console_write_u64(memory_usable_bytes() / (1024 * 1024));
    console_write(" MiB\nAllocated pages: ");
    console_write_u64(memory_allocated_pages());
    console_write("\n");
}

static __attribute__((noreturn)) void kernel_shell(void)
{
    char command[80];

    console_write("\nZAOD kernel monitor. Type 'help' for commands.\n");
    for (;;) {
        console_write("zaod> ");
        console_readline(command, sizeof(command));

        if (text_equals(command, "help")) {
            console_write("help  - list commands\n");
            console_write("info  - CPU and boot information\n");
            console_write("mem   - memory allocator status\n");
            console_write("page  - allocate and test a zeroed page\n");
            console_write("panic - test the CPU exception handler\n");
            console_write("sec   - test kernel security policy hooks\n");
            console_write("perm  - test the runtime permission broker\n");
            console_write("input - show queued keyboard/mouse events\n");
            console_write("gui   - redraw the onboarding screen\n");
            console_write("halt  - stop the processor\n");
        } else if (text_equals(command, "info")) {
            print_cpu_vendor();
            if (bootloader_request.response != 0) {
                console_write("Bootloader: ");
                console_write(bootloader_request.response->name);
                console_write(" ");
                console_write(bootloader_request.response->version);
                console_write("\n");
            }
            if (cmdline_request.response != 0 &&
                cmdline_request.response->cmdline != 0) {
                console_write("Boot options: ");
                console_write(cmdline_request.response->cmdline);
                console_write("\n");
            }
            print_memory_info();
        } else if (text_equals(command, "mem")) {
            print_memory_info();
        } else if (text_equals(command, "page")) {
            uint64_t physical_address;
            volatile uint64_t *page = memory_alloc_page(&physical_address);
            if (page == 0) {
                console_write("ERROR: out of usable physical pages\n");
            } else {
                page[0] = 0x5a414f4450414745;
                bool passed = page[0] == 0x5a414f4450414745;
                page[0] = 0;
                console_write(passed ? "Page test passed at " : "Page test failed at ");
                console_write_hex(physical_address);
                console_write("\n");
            }
        } else if (text_equals(command, "panic")) {
            __asm__ volatile ("int3");
        } else if (text_equals(command, "sec")) {
            const struct security_subject user_task = {
                .pid = 42,
                .uid = 1000,
                .capabilities = 0,
                .app_id = "monitor.test"
            };
            const struct security_subject system_task = {
                .pid = 1,
                .uid = 0,
                .capabilities = SECURITY_CAP_SYSTEM
            };
            bool protected_write_denied =
                security_check(SECURITY_OP_FILE_WRITE, &user_task,
                               "/etc/zaod.conf", false) ==
                SECURITY_DECISION_DENY;
            bool unverified_exec_denied =
                security_check(SECURITY_OP_EXEC, &user_task,
                               "/tmp/unknown", false) ==
                SECURITY_DECISION_DENY;
            bool module_load_denied =
                security_check(SECURITY_OP_MODULE_LOAD, &user_task,
                               0, false) == SECURITY_DECISION_DENY;
            bool system_write_allowed =
                security_check(SECURITY_OP_FILE_WRITE, &system_task,
                               "/etc/zaod.conf", false) ==
                SECURITY_DECISION_ALLOW;

            if (protected_write_denied && unverified_exec_denied &&
                module_load_denied && system_write_allowed) {
                console_write("Security policy self-test passed.\n");
            } else {
                console_write("ERROR: security policy self-test failed.\n");
            }
        } else if (text_equals(command, "perm")) {
            const struct permission_manifest_policy policy = {
                .app_id = "monitor.test",
                .resources = {
                    [PERMISSION_CAMERA] = PERMISSION_POLICY_WHILE_USING
                },
                .background_access = false
            };
            const uint64_t test_pid = 4242;
            permission_process_exit(test_pid);
            if (!permission_register_app(&policy) ||
                !permission_process_start(test_pid, policy.app_id, false) ||
                !permission_process_set_foreground(test_pid, true)) {
                console_write("ERROR: could not initialize permission test.\n");
            } else {
                bool granted = permission_request(
                    test_pid,
                    PERMISSION_CAMERA,
                    console_permission_prompt,
                    0
                );
                permission_process_set_foreground(test_pid, false);
                console_write(granted
                    ? "Permission was granted for this foreground session.\n"
                    : "Permission was denied.\n");
                permission_process_exit(test_pid);
            }
        } else if (text_equals(command, "input")) {
            struct input_event event;
            while (input_event_pop(&event)) {
                if (event.type == INPUT_EVENT_KEY) {
                    console_write("Key: ");
                    if (event.key == '\n') {
                        console_write("enter");
                    } else if (event.key == '\b') {
                        console_write("backspace");
                    } else {
                        char key[2] = {event.key, '\0'};
                        console_write(key);
                    }
                    console_write("\n");
                } else {
                    console_write("Mouse dx=");
                    console_write_u64((uint16_t)event.mouse_dx);
                    console_write(" dy=");
                    console_write_u64((uint16_t)event.mouse_dy);
                    console_write(" buttons=");
                    console_write_u64(event.mouse_buttons);
                    console_write("\n");
                }
            }
        } else if (text_equals(command, "gui")) {
            framebuffer_draw_onboarding();
            console_write(framebuffer_ready()
                ? "Onboarding screen redrawn.\n"
                : "No supported linear framebuffer is available.\n");
        } else if (text_equals(command, "halt")) {
            console_write("CPU halted.\n");
            halt_forever();
        } else if (command[0] != '\0') {
            console_write("Unknown command. Type 'help'.\n");
        }
    }
}

static void kernel_shell_task(void *argument)
{
    (void)argument;
    kernel_shell();
}

__attribute__((noreturn))
void kernel_main(void)
{
    console_init();
    permission_engine_init();
    console_write("\nZAOD custom kernel v0.2\n");
    permission_engine_init();
    task_scheduler_init();
    syscall_init();
    syscall_set_permission_prompt(console_permission_prompt);

    if (!gdt_init()) {
        console_write("ERROR: CPU lacks required NX page protection support\n");
        halt_forever();
    }
    console_write("GDT, ring-3 descriptors, TSS and NX: ready\n");

    if (!LIMINE_BASE_REVISION_SUPPORTED(base_revision)) {
        console_write("ERROR: unsupported Limine base revision\n");
        halt_forever();
    }
    console_write("Limine protocol: ready\n");

    if (bootloader_request.response != 0) {
        console_write("Bootloader: ");
        console_write(bootloader_request.response->name);
        console_write(" ");
        console_write(bootloader_request.response->version);
        console_write("\n");
    }

    if (cmdline_request.response != 0 &&
        cmdline_request.response->cmdline != 0) {
        console_write("Boot options: ");
        console_write(cmdline_request.response->cmdline);
        console_write("\n");
    }

    if (!memory_init(memmap_request.response, hhdm_request.response)) {
        console_write("ERROR: Limine memory map or HHDM response is missing\n");
        halt_forever();
    }
    if (!address_space_init()) {
        console_write("ERROR: could not capture the kernel page table root\n");
        halt_forever();
    }

    if (framebuffer_request.response != 0 &&
        framebuffer_request.response->framebuffer_count != 0 &&
        framebuffer_request.response->framebuffers != 0 &&
        framebuffer_request.response->framebuffers[0] != 0 &&
        framebuffer_init(framebuffer_request.response->framebuffers[0])) {
        framebuffer_draw_onboarding();
        console_write("Linear framebuffer: ready\n");
    } else {
        console_write("Linear framebuffer: unavailable or unsupported\n");
    }

    interrupts_init();
    console_write("CPU exceptions, timer, keyboard and syscall gate: ready\n");
    console_write(mouse_irq_available()
        ? "PS/2 mouse: ready\n"
        : "PS/2 mouse: unavailable\n");

    uint64_t physical_address = 0;
    volatile uint64_t *page = memory_alloc_page(&physical_address);
    if (page == 0) {
        console_write("ERROR: could not allocate a physical page\n");
        halt_forever();
    }
    page[0] = 0x5a414f444d454d31;
    if (page[0] != 0x5a414f444d454d31) {
        console_write("ERROR: physical page read/write test failed\n");
        halt_forever();
    }
    page[0] = 0;

    console_write("Physical page allocator: ready, first page at ");
    console_write_hex(physical_address);
    console_write("\n");

    if (module_request.response == 0 ||
        module_request.response->module_count == 0 ||
        module_request.response->modules == 0 ||
        module_request.response->modules[0] == 0) {
        console_write("ERROR: initramfs module was not loaded\n");
        halt_forever();
    }

    console_write("Initramfs module bytes: ");
    console_write_u64(module_request.response->modules[0]->size);
    console_write("\nKernel bring-up complete; preparing trusted ring-3 init.\n");
    struct limine_file *initramfs = module_request.response->modules[0];
    if (initramfs->address == 0 || initramfs->size > SIZE_MAX ||
        !vfs_init(initramfs->address, (size_t)initramfs->size)) {
        console_write("ERROR: initramfs CPIO could not be mounted\n");
        halt_forever();
    }
    console_write("Read-only initramfs VFS: mounted\n");
    if (ata_block_init()) {
        if (persistent_fs_mount()) {
            console_write("Persistent ZAODFS volume: mounted\n");
        } else {
            console_write("ATA disk found; persistent volume is not formatted\n");
        }
    } else {
        console_write("No ATA disk detected; persistent paths are unavailable\n");
    }

    const uint8_t *init_image;
    size_t init_image_size;
    uint64_t init_pid;
    if (!vfs_kernel_file("/sbin/init.elf", &init_image, &init_image_size) ||
        !elf64_spawn(NULL, true, init_image, init_image_size, &init_pid)) {
        console_write("ERROR: trusted init ELF failed integrity or load checks\n");
        halt_forever();
    }
    console_write("Trusted init SHA-256 integrity check passed\n");
    console_write("Trusted init.elf loaded as ring-3 task ");
    console_write_u64(init_pid);
    console_write("\n");

    uint64_t shell_pid;
    if (!task_spawn(NULL, true, kernel_shell_task, NULL, &shell_pid)) {
        console_write("ERROR: could not create kernel monitor task\n");
        halt_forever();
    }
    console_write("Round-robin kernel task scheduler: starting\n");
    task_scheduler_start();
}
