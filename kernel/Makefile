include .config

ifneq ($(ZAOD_ARCH),x86_64)
$(error ZAOD_ARCH must be x86_64)
endif

ROOT := ..
OUTPUT_DIR := $(ROOT)/build/kernel
KERNEL_OUTPUT := $(ROOT)/iso_root/kernel/zaod_kernel.elf
INITRAMFS_OUTPUT := $(ROOT)/iso_root/boot/initramfs.img
USER_OUTPUT_DIR := $(ROOT)/build/user
USER_INIT_OUTPUT := $(USER_OUTPUT_DIR)/init.elf
TRUSTED_INIT_HASH_HEADER := $(OUTPUT_DIR)/trusted_init_hash.h
ZSHIELD_HASH_HEADER := $(OUTPUT_DIR)/zshield_hashes.h
USER_CFLAGS := -O2 -std=c11 -Wall -Wextra -Werror -m64 -mno-red-zone -ffreestanding -fno-builtin -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables
ZAOD_ZSHIELD_DEFINITIONS ?=
ZAOD_ZSHIELD_SIGNATURE ?=
ZAOD_ZSHIELD_PUBLIC_KEY ?=

.PHONY: all kernel initramfs user-init test clean sdk-test FORCE

all: kernel initramfs

kernel: $(KERNEL_OUTPUT)

initramfs: $(INITRAMFS_OUTPUT)

user-init: $(USER_INIT_OUTPUT)

$(OUTPUT_DIR):
	mkdir -p "$@"

$(USER_OUTPUT_DIR):
	mkdir -p "$@"

$(USER_OUTPUT_DIR)/init.o: ../userspace/init.c | $(USER_OUTPUT_DIR)
	$(ZAOD_CC) $(USER_CFLAGS) -c "$<" -o "$@"

$(USER_INIT_OUTPUT): $(USER_OUTPUT_DIR)/init.o ../userspace/linker.ld
	$(ZAOD_LD) -nostdlib -static -z max-page-size=0x1000 -T ../userspace/linker.ld -o "$@" $(USER_OUTPUT_DIR)/init.o

$(TRUSTED_INIT_HASH_HEADER): $(USER_INIT_OUTPUT) ../tools/gen_init_hash.py | $(OUTPUT_DIR)
	python3 ../tools/gen_init_hash.py "$(USER_INIT_OUTPUT)" "$@"

$(ZSHIELD_HASH_HEADER): FORCE ../tools/gen_zshield_hashes.py ../tools/z_shield.py ../tools/zpkg.py | $(OUTPUT_DIR)
	ZAOD_ZSHIELD_DEFINITIONS="$(ZAOD_ZSHIELD_DEFINITIONS)" \
	ZAOD_ZSHIELD_SIGNATURE="$(ZAOD_ZSHIELD_SIGNATURE)" \
	ZAOD_ZSHIELD_PUBLIC_KEY="$(ZAOD_ZSHIELD_PUBLIC_KEY)" \
	python3 ../tools/gen_zshield_hashes.py --output "$@"

FORCE:

$(OUTPUT_DIR)/boot.o: src/boot.S .config | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_ASFLAGS) -c "$<" -o "$@"

$(OUTPUT_DIR)/main.o: src/main.c .config include/address_space.h include/block.h include/console.h include/elf.h include/framebuffer.h include/gdt.h include/input.h include/interrupts.h include/memory.h include/permissions.h include/persistent_fs.h include/security.h include/syscall.h include/task.h include/vfs.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I../tools/limine-protocol -c "$<" -o "$@"

$(OUTPUT_DIR)/console.o: src/console.c .config include/console.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/gdt.o: src/gdt.c .config include/gdt.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/memory.o: src/memory.c .config include/console.h include/memory.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I../tools/limine-protocol -c "$<" -o "$@"

$(OUTPUT_DIR)/ata.o: src/ata.c .config include/block.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/persistent_fs.o: src/persistent_fs.c .config include/block.h include/persistent_fs.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/address_space.o: src/address_space.c .config include/address_space.h include/memory.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I../tools/limine-protocol -c "$<" -o "$@"

$(OUTPUT_DIR)/elf.o: src/elf.c .config include/address_space.h include/elf.h include/memory.h include/security.h include/task.h include/zshield.h $(TRUSTED_INIT_HASH_HEADER) | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I"$(OUTPUT_DIR)" -I../tools/limine-protocol -c "$<" -o "$@"

$(OUTPUT_DIR)/sha256.o: src/sha256.c .config include/sha256.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/ed25519.o: crypto/ed25519.c crypto/ed25519.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Icrypto -c "$<" -o "$@"

$(OUTPUT_DIR)/chacha20.o: crypto/chacha20.c crypto/chacha20.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Icrypto -c "$<" -o "$@"

$(OUTPUT_DIR)/zaod_format.o: loader/zaod_format.c loader/zaod_format.h crypto/ed25519.h crypto/zaod_keys.h include/sha256.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Icrypto -Iinclude -Iloader -c "$<" -o "$@"

$(OUTPUT_DIR)/exec_zaod.o: loader/exec_zaod.c loader/exec_zaod.h loader/zaod_format.h crypto/zaod_keys.h include/elf.h include/permissions.h include/sha256.h include/task.h include/vfs.h include/zshield.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Icrypto -Iinclude -Iloader -c "$<" -o "$@"

$(OUTPUT_DIR)/zshield.o: src/zshield.c .config include/sha256.h include/zshield.h $(TRUSTED_INIT_HASH_HEADER) $(ZSHIELD_HASH_HEADER) | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I"$(OUTPUT_DIR)" -c "$<" -o "$@"

$(OUTPUT_DIR)/interrupts.o: src/interrupts.c .config include/address_space.h include/console.h include/gdt.h include/input.h include/interrupts.h include/syscall.h include/task.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/interrupts_asm.o: src/interrupts.S .config | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_ASFLAGS) -c "$<" -o "$@"

$(OUTPUT_DIR)/security.o: src/security.c .config include/console.h include/security.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/permissions.o: src/permissions.c .config include/console.h include/permissions.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/task.o: src/task.c .config include/gdt.h include/permissions.h include/task.h include/vfs.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/vfs.o: src/vfs.c .config include/permissions.h include/persistent_fs.h include/security.h include/sha256.h include/task.h include/vfs.h include/zshield.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/syscall.o: src/syscall.c .config include/address_space.h include/framebuffer.h include/input.h include/permissions.h include/security.h include/syscall.h include/task.h include/vfs.h loader/exec_zaod.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I../tools/limine-protocol -c "$<" -o "$@"

$(OUTPUT_DIR)/input.o: src/input.c .config include/input.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -c "$<" -o "$@"

$(OUTPUT_DIR)/framebuffer.o: src/framebuffer.c .config include/framebuffer.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(ZAOD_CC) $(ZAOD_CFLAGS) -Iinclude -I../tools/limine-protocol -c "$<" -o "$@"

$(KERNEL_OUTPUT): $(OUTPUT_DIR)/boot.o $(OUTPUT_DIR)/main.o $(OUTPUT_DIR)/console.o $(OUTPUT_DIR)/memory.o $(OUTPUT_DIR)/ata.o $(OUTPUT_DIR)/persistent_fs.o $(OUTPUT_DIR)/address_space.o $(OUTPUT_DIR)/elf.o $(OUTPUT_DIR)/sha256.o $(OUTPUT_DIR)/ed25519.o $(OUTPUT_DIR)/chacha20.o $(OUTPUT_DIR)/zaod_format.o $(OUTPUT_DIR)/exec_zaod.o $(OUTPUT_DIR)/zshield.o $(OUTPUT_DIR)/gdt.o $(OUTPUT_DIR)/interrupts.o $(OUTPUT_DIR)/interrupts_asm.o $(OUTPUT_DIR)/security.o $(OUTPUT_DIR)/permissions.o $(OUTPUT_DIR)/task.o $(OUTPUT_DIR)/vfs.o $(OUTPUT_DIR)/syscall.o $(OUTPUT_DIR)/input.o $(OUTPUT_DIR)/framebuffer.o linker.ld
	mkdir -p "$(dir $@)"
	$(ZAOD_LD) -nostdlib -static -z max-page-size=0x1000 -T linker.ld -o "$@" $(OUTPUT_DIR)/boot.o $(OUTPUT_DIR)/main.o $(OUTPUT_DIR)/console.o $(OUTPUT_DIR)/memory.o $(OUTPUT_DIR)/ata.o $(OUTPUT_DIR)/persistent_fs.o $(OUTPUT_DIR)/address_space.o $(OUTPUT_DIR)/elf.o $(OUTPUT_DIR)/sha256.o $(OUTPUT_DIR)/ed25519.o $(OUTPUT_DIR)/chacha20.o $(OUTPUT_DIR)/zaod_format.o $(OUTPUT_DIR)/exec_zaod.o $(OUTPUT_DIR)/zshield.o $(OUTPUT_DIR)/gdt.o $(OUTPUT_DIR)/interrupts.o $(OUTPUT_DIR)/interrupts_asm.o $(OUTPUT_DIR)/security.o $(OUTPUT_DIR)/permissions.o $(OUTPUT_DIR)/task.o $(OUTPUT_DIR)/vfs.o $(OUTPUT_DIR)/syscall.o $(OUTPUT_DIR)/input.o $(OUTPUT_DIR)/framebuffer.o

$(INITRAMFS_OUTPUT): ../tools/mkinitramfs.py $(USER_INIT_OUTPUT)
	python3 ../tools/mkinitramfs.py "$@" "$(USER_INIT_OUTPUT)"

$(OUTPUT_DIR)/security-test: ../tests/kernel_security.c src/security.c include/console.h include/security.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude ../tests/kernel_security.c src/security.c -o "$@"

$(OUTPUT_DIR)/permissions-test: ../tests/kernel_permissions.c src/permissions.c include/console.h include/permissions.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude ../tests/kernel_permissions.c src/permissions.c -o "$@"

$(OUTPUT_DIR)/scheduler-test: ../tests/kernel_scheduler.c src/task.c src/vfs.c src/persistent_fs.c src/sha256.c src/zshield.c src/security.c src/permissions.c include/block.h include/console.h include/gdt.h include/permissions.h include/persistent_fs.h include/security.h include/sha256.h include/task.h include/vfs.h include/zshield.h $(TRUSTED_INIT_HASH_HEADER) $(ZSHIELD_HASH_HEADER) | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -I"$(OUTPUT_DIR)" ../tests/kernel_scheduler.c src/task.c src/vfs.c src/persistent_fs.c src/sha256.c src/zshield.c src/security.c src/permissions.c -o "$@"

$(OUTPUT_DIR)/framebuffer-test: ../tests/kernel_framebuffer.c src/framebuffer.c include/framebuffer.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -I../tools/limine-protocol ../tests/kernel_framebuffer.c src/framebuffer.c -o "$@"

$(OUTPUT_DIR)/vfs-syscall-test: ../tests/kernel_vfs_syscalls.c src/task.c src/vfs.c src/syscall.c src/address_space.c src/memory.c src/persistent_fs.c src/sha256.c src/zshield.c src/security.c src/permissions.c src/framebuffer.c src/input.c include/address_space.h include/block.h include/console.h include/framebuffer.h include/input.h include/memory.h include/permissions.h include/persistent_fs.h include/security.h include/sha256.h include/syscall.h include/task.h include/vfs.h include/zshield.h ../tests/fixtures/zshield_hashes.h $(TRUSTED_INIT_HASH_HEADER) ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -I../tests/fixtures -I"$(OUTPUT_DIR)" -I../tools/limine-protocol ../tests/kernel_vfs_syscalls.c src/task.c src/vfs.c src/syscall.c src/address_space.c src/memory.c src/persistent_fs.c src/sha256.c src/zshield.c src/security.c src/permissions.c src/framebuffer.c src/input.c -o "$@"

$(OUTPUT_DIR)/address-space-test: ../tests/kernel_address_space.c src/address_space.c src/memory.c include/address_space.h include/console.h include/memory.h ../tools/limine-protocol/limine.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -I../tools/limine-protocol ../tests/kernel_address_space.c src/address_space.c src/memory.c -o "$@"

$(OUTPUT_DIR)/persistent-fs-test: ../tests/kernel_persistent_fs.c src/persistent_fs.c include/block.h include/persistent_fs.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude ../tests/kernel_persistent_fs.c src/persistent_fs.c -o "$@"

$(OUTPUT_DIR)/zshield-test: ../tests/kernel_zshield.c src/sha256.c src/zshield.c include/sha256.h include/zshield.h $(TRUSTED_INIT_HASH_HEADER) $(ZSHIELD_HASH_HEADER) $(USER_INIT_OUTPUT) | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -I"$(OUTPUT_DIR)" ../tests/kernel_zshield.c src/sha256.c src/zshield.c -o "$@"

$(OUTPUT_DIR)/crypto-test: tests/crypto_test.c crypto/ed25519.c loader/zaod_format.c src/sha256.c crypto/ed25519.h crypto/zaod_keys.h loader/zaod_format.h include/sha256.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Icrypto -Iloader -Iinclude tests/crypto_test.c crypto/ed25519.c loader/zaod_format.c src/sha256.c -o "$@"

$(OUTPUT_DIR)/chacha-test: tests/chacha20poly1305_test.c crypto/chacha20.c crypto/chacha20.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -Icrypto tests/chacha20poly1305_test.c crypto/chacha20.c -o "$@"

$(OUTPUT_DIR)/exec_zaod_test.o: loader/exec_zaod.c loader/exec_zaod.h loader/zaod_format.h crypto/zaod_keys.h include/permissions.h include/sha256.h include/task.h include/vfs.h include/zshield.h | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Icrypto -Iinclude -Iloader -c loader/exec_zaod.c -o "$(OUTPUT_DIR)/exec_zaod_test.o"

$(OUTPUT_DIR)/zaod-manifest-test: ../tests/kernel_zaod_manifest.c $(OUTPUT_DIR)/exec_zaod_test.o | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Icrypto -Iinclude -Iloader ../tests/kernel_zaod_manifest.c "$(OUTPUT_DIR)/exec_zaod_test.o" -Wl,--gc-sections -o "$@"

$(OUTPUT_DIR)/flat-package-verify: tests/flat_package_verify.c $(OUTPUT_DIR)/exec_zaod_test.o crypto/ed25519.c loader/zaod_format.c src/sha256.c | $(OUTPUT_DIR)
	$(CC) -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Icrypto -Iinclude -Iloader tests/flat_package_verify.c "$(OUTPUT_DIR)/exec_zaod_test.o" crypto/ed25519.c loader/zaod_format.c src/sha256.c -Wl,--gc-sections -o "$@"

test: $(OUTPUT_DIR)/security-test $(OUTPUT_DIR)/permissions-test $(OUTPUT_DIR)/scheduler-test $(OUTPUT_DIR)/framebuffer-test $(OUTPUT_DIR)/vfs-syscall-test $(OUTPUT_DIR)/address-space-test $(OUTPUT_DIR)/persistent-fs-test $(OUTPUT_DIR)/zshield-test $(OUTPUT_DIR)/crypto-test $(OUTPUT_DIR)/chacha-test $(OUTPUT_DIR)/zaod-manifest-test $(OUTPUT_DIR)/flat-package-verify $(INITRAMFS_OUTPUT)
	"$(OUTPUT_DIR)/security-test"
	"$(OUTPUT_DIR)/permissions-test"
	"$(OUTPUT_DIR)/scheduler-test"
	"$(OUTPUT_DIR)/framebuffer-test"
	"$(OUTPUT_DIR)/vfs-syscall-test"
	"$(OUTPUT_DIR)/address-space-test"
	"$(OUTPUT_DIR)/persistent-fs-test"
	"$(OUTPUT_DIR)/zshield-test"
	"$(OUTPUT_DIR)/crypto-test"
	"$(OUTPUT_DIR)/chacha-test"
	"$(OUTPUT_DIR)/zaod-manifest-test"
	python3 ../tests/test_zpkg.py
	python3 ../tests/test_gen_keys.py
	ZAOD_KERNEL_PACKAGE_VERIFY="$(OUTPUT_DIR)/flat-package-verify" python3 ../tests/test_zaodc.py
	python3 ../tests/test_initramfs.py "$(INITRAMFS_OUTPUT)"
	bash ../tests/test_ring3_qemu.sh

sdk-test:
	python3 ../tests/test_zaodc.py

clean:
	rm -f "$(OUTPUT_DIR)"/*.o "$(OUTPUT_DIR)"/trusted_init_hash.h "$(OUTPUT_DIR)"/zshield_hashes.h "$(KERNEL_OUTPUT)" "$(INITRAMFS_OUTPUT)" "$(USER_OUTPUT_DIR)"/*.o "$(USER_INIT_OUTPUT)"
	rmdir "$(OUTPUT_DIR)" 2>/dev/null || true
	rmdir "$(USER_OUTPUT_DIR)" 2>/dev/null || true
