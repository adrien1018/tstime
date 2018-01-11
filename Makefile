CFLAGS = -Wall -g -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE

TEMP = tstime.o taskstat.o tools.o tstime

.PHONY: all
all: tstime

tstime: tstime.o taskstat.o tools.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

tstime.o taskstat.o tstime.c taskstat.c: taskstat.h
tstime.o tstime.c : tools.h

.PHONY: clean
clean:
	rm -f $(TEMP)

