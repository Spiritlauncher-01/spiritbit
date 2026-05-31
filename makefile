CC     = gcc
CLANG  = clang
CFLAGS = -Wall -Wextra -Wpedantic -Wstrict-prototypes -g -O2
LDFLAGS = -lbpf -lelf -lz -lm -lpthread \
          -lcap -lsqlite3 -lcrypto
BPF_PATH = /usr/lib/spiritbit/spiritbit.bpf.o
all: spiritbit.bpf.o spiritbit spiritbit_watchdog
# Compile kernel side eBPF
# Must use clang, not gcc
# -target bpf: compile for BPF virtual machine
# -O2: required for eBPF verifier to accept loops
spiritbit.bpf.o: spiritbit.bpf.c $(CLANG) \
        -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include \
        -O2 -g \
        -w \
        -c spiritbit.bpf.c \
        -o spiritbit.bpf.o
# Compile userspace daemon
spiritbit: spiritbit.c $(CC) $(CFLAGS) spiritbit.c -o spiritbit $(LDFLAGS)
# Compile watchdog
spiritbit_watchdog: spiritbit_watchdog.c $(CC) $(CFLAGS) spiritbit_watchdog.c \
        -o spiritbit_watchdog
# Install to system paths
install: all 
    mkdir -p /usr/lib/spiritbit
    mkdir -p /var/lib/spiritbit
    mkdir -p /var/log
    mkdir -p /etc/spiritbit
    install -m 755 spiritbit /usr/bin/spiritbit
    install -m 755 spiritbit_watchdog \
        /usr/bin/spiritbit_watchdog
    install -m 644 spiritbit.bpf.o $(BPF_PATH)
    # Set ownership: root only
    chown root:root /usr/bin/spiritbit
    chown root:root $(BPF_PATH)
    chmod 700 /var/lib/spiritbit
    # Install default config if not exists
    if [ ! -f /etc/spiritbit/config.conf ]; then \
        install -m 644 config.conf.default \
            /etc/spiritbit/config.conf; \
    fi
    @echo "Installation complete"
    @echo "Run: sudo spiritbit"
clean:
    rm -f spiritbit spiritbit.bpf.o spiritbit_watchdog
# Install dependencies on Fedora
deps-fedora:
    sudo dnf install -y \
        clang llvm \
        libbpf libbpf-devel \
        kernel-devel \
        elfutils-libelf-devel \
        zlib-devel \
        libcap-devel \
        sqlite-devel \
        openssl-devel \
        bpftool
# Install dependencies on Ubuntu/Debian
deps-ubuntu:
    sudo apt install -y \
        clang llvm \
        libbpf-dev \
        linux-headers-$(uname -r) \
        libelf-dev zlib1g-dev \
        libcap-dev \
        libsqlite3-dev \
        libssl-dev \
        linux-tools-$(uname -r)
