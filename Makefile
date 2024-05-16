CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wvla -O3 -flto -fno-strict-aliasing -ffunction-sections -fdata-sections -DNDEBUG
LDFLAGS = -O3 -flto -fno-strict-aliasing -Wl,--gc-sections -s
LIBS = -lm
SRCS = dns2tcp.c libev/ev.c
OBJS = $(SRCS:.c=.o)
MAIN = dns2tcp
DESTDIR = /usr/local/bin

.PHONY: all install clean

all: $(MAIN)

install: $(MAIN)
	mkdir -p $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)

clean:
	$(RM) $(MAIN) *.o libev/*.o

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(MAIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
