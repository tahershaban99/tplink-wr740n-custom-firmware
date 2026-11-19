CC ?= gcc
CFLAGS ?= -Os -Wall -Wextra -std=gnu99 -ffunction-sections -fdata-sections
LDFLAGS ?= -lpthread -ldl -Wl,--gc-sections

SRCS = main.c meter.c firewall.c telegram.c json_util.c fazakkir.c
OBJS = $(SRCS:.c=.o)
CGI_OBJS = rmeter_cgi.o json_util.o
TARGET = rmeterd
CGI_TARGET = rmeter_cgi

all: $(TARGET) $(CGI_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CGI_TARGET): $(CGI_OBJS)
	$(CC) $(CFLAGS) -Wl,--gc-sections -o $@ $^

%.o: %.c rmeter.h json_util.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) rmeter_cgi.o $(TARGET) $(CGI_TARGET)

