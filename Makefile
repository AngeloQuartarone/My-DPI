SHELL=/bin/bash
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -g
VFLAGS=--leak-check=full --show-leak-kinds=all --track-origins=yes -s
.PHONY: clean

default: dpi

dpi: dpi.o ./lib/hashMap.o ./lib/dpi_utils.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

dpi_utils: dpi_utils.o
	$(CC) $(CFLAGS) $^ -o $@ 

clean:
	rm -f dpi *.o ./lib/*.o

dpi.o: dpi.c ./lib/hashMap.h
hashMap.o: ./lib/hashMap.c ./lib/hashMap.h
dpi_utils.o: ./lib/dpi_utils.c ./lib/dpi_utils.h


