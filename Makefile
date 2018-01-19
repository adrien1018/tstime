CC = gcc
CFLAGS = -Wall -std=c99 -O2 -D_XOPEN_SOURCE -D_GNU_SOURCE
CLIBS = -lseccomp

OBJ_FILES = tstime.o taskstat.o tools.o
TEMP = $(OBJ_FILES) tstime

.PHONY: all
all: tstime

tstime: $(OBJ_FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(CLIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@	

tstime.c taskstat.c: taskstat.h
tstime.c : tools.h

.PHONY: clean
clean:
	rm -f $(TEMP)

