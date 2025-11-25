# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic -O2 -Icommon -Ibotan_cmac/include -Ibotan_cmac/include/botan-3
LDFLAGS := -pthread -lrt -ldl

# Library path and static library
LIB := botan_cmac/lib/libbotan-3.a

# Directories
SENDER_DIR := sender
RECEIVER_DIR := receiver
OUT_DIR := output

# Sources
SENDER_SRC := $(SENDER_DIR)/sender.cpp
RECEIVER_SRC := $(RECEIVER_DIR)/receiver.cpp

# Objects
SENDER_OBJ := $(OUT_DIR)/sender.o
RECEIVER_OBJ := $(OUT_DIR)/receiver.o

# Binaries
SENDER_BIN := $(OUT_DIR)/sender
RECEIVER_BIN := $(OUT_DIR)/receiver

# Number of jobs for parallel build (optional)
JOBS ?= 1

# Ensure required library exists
ifeq ($(wildcard $(LIB)),)
$(error Required library '$(LIB)' not found. Build botan_cmac or set LIB path.)
endif

# Default target
all: $(OUT_DIR) $(SENDER_BIN) $(RECEIVER_BIN)

# Create output directory
$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Build sender object
$(SENDER_OBJ): $(SENDER_SRC) | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Build receiver object
$(RECEIVER_OBJ): $(RECEIVER_SRC) | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link sender
$(SENDER_BIN): $(SENDER_OBJ) | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LIB)

# Link receiver
$(RECEIVER_BIN): $(RECEIVER_OBJ) | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LIB)

# Clean binaries/objects
clean:
	rm -rf $(OUT_DIR)/*

.PHONY: all clean

