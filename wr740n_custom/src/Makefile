CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu99
LDFLAGS ?= -lpthread -ldl

SRCS = main.c meter.c firewall.c telegram.c json_util.c fazakkir.c
OBJS = $(SRCS:.c=.o)
CGI_OBJS = rmeter_cgi.o json_util.o
TARGET = rmeterd
CGI_TARGET = rmeter_cgi

all: $(TARGET) $(CGI_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CGI_TARGET): $(CGI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c rmeter.h json_util.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) rmeter_cgi.o $(TARGET) $(CGI_TARGET)

