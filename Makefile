SHELL=/bin/bash
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -g
VFLAGS=--leak-check=full --show-leak-kinds=all --track-origins=yes -s
.PHONY: clean

default: dpi

dpi: dpi.o ./lib/hashMap.o ./lib/dpi_utils.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

dpi.o: dpi.c ./lib/hashMap.h ./lib/dpi_utils.h
	$(CC) $(CFLAGS) -c dpi.c -o dpi.o

./lib/hashMap.o: ./lib/hashMap.c ./lib/hashMap.h
	$(CC) $(CFLAGS) -c ./lib/hashMap.c -o ./lib/hashMap.o

./lib/dpi_utils.o: ./lib/dpi_utils.c ./lib/dpi_utils.h
	$(CC) $(CFLAGS) -c ./lib/dpi_utils.c -o ./lib/dpi_utils.o

clean:
	rm -f dpi *.o ./lib/*.o



