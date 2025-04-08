SGX_SDK ?= /opt/intel/sgxsdk

CC = gcc
CFLAGS = -Wall -Wextra -pthread -I../ -I../../include -I$(SGX_SDK)/include -IEnclave
LDFLAGS = -lpthread -lsgx_urts

SRCS = test_connection.c
OBJS = $(SRCS:.c=.o)
TARGET = test_connection

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) 