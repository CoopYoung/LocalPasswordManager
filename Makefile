CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -std=c11 -O2 -g -Iexternal
LDFLAGS := -lsodium

TARGET := cbw
SRCS     := cbw.c external/cJSON.c
OBJS     := $(SRCS:.c=.o)

# Installation paths
PREFIX   ?= ~/.local
BINDIR   := $(PREFIX)/bin

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
	@echo "Build complete: ./$(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Cleaned build artifacts"

install: $(TARGET)
	mkdir -p $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	@echo "Installed to $(BINDIR)/$(TARGET)"
	@echo "Make sure $(BINDIR) is in your PATH"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	@echo "Uninstalled cbw"

# Debug build
debug:
	$(MAKE) CFLAGS="$(CFLAGS) -O0 -g3 -fsanitize=address,undefined" LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined"

# Run with example
run-gen:
	./$(TARGET) gen 5 -u hero8 -l grok.com