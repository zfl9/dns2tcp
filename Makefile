CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O3
SRCS = dns2tcp.c
OBJS = $(SRCS:.c=.o)
MAIN = dns2tcp
DESTDIR = /usr/local/bin

.PHONY: all install clean

all: $(MAIN)

install: $(MAIN)
	mkdir -p $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)

clean:
	$(RM) *.o $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) -s $(OBJS) -o $(MAIN)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
