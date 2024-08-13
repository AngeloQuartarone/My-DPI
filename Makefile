SHELL=/bin/bash
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -g
VFLAGS=--leak-check=full --show-leak-kinds=all --track-origins=yes -s
.PHONY: clean

default: dpi

dpi: dpi.o ./lib/hashMap.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

clean:
	rm -f dpi *.o ./lib/*.o

dpi.o: dpi.c ./lib/hashMap.h
hashMap.o: ./lib/hashMap.c ./lib/hashMap.h


