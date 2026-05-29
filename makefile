# Makefile - Spiritbit v4.4 Full Build System
# Optimized for maximum features while staying under 20MB RAM

CC = gcc
CFLAGS = -Wall -Wextra -O2 -static -pthread -fPIE
BPF_CFLAGS = -target bpf -mcpu=v3 -O2 -g

# Libraries
LIBS = -lbpf -lsqlite3 -lcap

# Installation paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
LIBDIR = /var/lib/spiritbit
LOGDIR = /var/log/spiritbit

all: spiritbit.bpf.o spiritbit spiritbitwatchdog

# ====================== BPF KERNEL OBJECT ======================
spiritbit.bpf.o: spiritbit.bpf.c
	@echo "Compiling eBPF kernel object..."
	clang $(BPF_CFLAGS) -c $< -o $@
	@echo "BPF object compiled successfully."

# ====================== MAIN DAEMON ======================
spiritbit: spiritbit.c config.h
	@echo "Compiling main daemon (spiritbit.c)..."
	$(CC) $(CFLAGS) spiritbit.c -o $@ $(LIBS)
	@echo "Main daemon compiled."

# ====================== WATCHDOG ======================
spiritbitwatchdog: spiritbitwatchdog.c
	@echo "Compiling watchdog..."
	$(CC) $(CFLAGS) spiritbitwatchdog.c -o $@ 
	@echo "Watchdog compiled."

# ====================== INSTALL ======================
install: all
	@echo "Installing Spiritbit..."
	mkdir -p $(BINDIR)
	mkdir -p $(LIBDIR)
	mkdir -p $(LOGDIR)
	mkdir -p $(LIBDIR)/quarantine
	
	cp spiritbit $(BINDIR)/spiritbit
	cp spiritbitwatchdog $(BINDIR)/spiritbitwatchdog
	cp spiritbit.bpf.o $(LIBDIR)/
	
	# Set permissions
	chmod 755 $(BINDIR)/spiritbit
	chmod 755 $(BINDIR)/spiritbitwatchdog
	chmod 700 $(LIBDIR)
	chmod 700 $(LOGDIR)
	
	@echo "Spiritbit v4.4 installed successfully!"
	@echo "Run with: sudo $(BINDIR)/spiritbitwatchdog &"

# ====================== CLEAN ======================
clean:
	@echo "Cleaning build files..."
	rm -f *.o spiritbit spiritbitwatchdog spiritbit.bpf.o
	@echo "Clean completed."

# ====================== UNINSTALL ======================
uninstall:
	@echo "Uninstalling Spiritbit..."
	rm -f $(BINDIR)/spiritbit
	rm -f $(BINDIR)/spiritbitwatchdog
	rm -rf $(LIBDIR)
	rm -rf $(LOGDIR)
	@echo "Uninstall completed."

# ====================== STATUS ======================
status:
	@echo "=== Spiritbit v4.4 Build Status ==="
	@echo "Main Daemon      : spiritbit"
	@echo "Watchdog         : spiritbitwatchdog"
	@echo "BPF Object       : spiritbit.bpf.o"
	@echo "Memory Target    : < 20MB"
	@echo "Features         : Full (Ancestry, SQLite, ML, Dual Watchdog, Rate Limiting)"

.PHONY: all clean install uninstall status
