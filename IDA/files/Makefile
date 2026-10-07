# The build the locker shipped with.
CC      ?= gcc
CFLAGS  ?= -O2 -s -Wall
TARGET  ?= encryptor

.PHONY: all clean

all: $(TARGET)

$(TARGET): encryptor.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
