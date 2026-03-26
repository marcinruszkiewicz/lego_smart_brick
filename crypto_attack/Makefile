CC      ?= cc
CFLAGS  ?= -O3 -march=native -Wall -Wextra -Wno-unused-function
LDFLAGS ?= -lpthread

TARGET  = grain_attack
SRCS    = grain128a.c grain128a_bs.c attack.c
OBJS    = $(SRCS:.c=.o)
HDRS    = grain128a.h grain128a_bs.h

.PHONY: all clean verify benchmark

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

verify: $(TARGET)
	./$(TARGET) --verify

benchmark: $(TARGET)
	./$(TARGET) --verify --benchmark

clean:
	rm -f $(OBJS) $(TARGET)
