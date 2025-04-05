CC = gcc
CFLAGS = -Wall -Wextra -pthread -I./include
LDFLAGS = -pthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
EXAMPLE_DIR = examples

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Example source
EXAMPLE_SRC = $(EXAMPLE_DIR)/main.c
EXAMPLE_OBJ = $(EXAMPLE_SRC:$(EXAMPLE_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/p2p_example

.PHONY: all clean directories

all: directories $(TARGET)

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(EXAMPLE_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(EXAMPLE_OBJ)
	$(CC) $(OBJS) $(EXAMPLE_OBJ) -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) 