# Makefile for the Secure P2P File Transfer Application

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g # -Wall and -Wextra for all warnings, -g for debugging
LDFLAGS = -lssl -lcrypto -lpthread

# Source files
SRCS = main.c crypto.c network.c server.c client.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = secure_p2p

# Default target
all: $(TARGET)

# Linking the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compiling source files into object files
%.o: %.c peer.h
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean
