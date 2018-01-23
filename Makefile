CC = gcc
CFLAGS = -Wall -std=c99 -static -O2 -D_XOPEN_SOURCE -D_GNU_SOURCE
CLIBS = -lseccomp

OBJ_FILES = tstime.o taskstat.o tools.o
EXE = tstime

.PHONY: all clean
all: $(EXE)

$(EXE): $(OBJ_FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(CLIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@	

tstime.c taskstat.c: taskstat.h
tstime.c: tools.h

clean:
	rm -f $(EXE) $(OBJ_FILES)
