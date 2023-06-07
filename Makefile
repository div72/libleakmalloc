CC ?= gcc
CFLAGS ?= -shared -O2 -Wall -Werror -std=gnu11

src/libleakmalloc.so: $(wildcard src/*.c)
	$(CC) $(CFLAGS) -o $@ $^
