# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Iinclude/botan-3

# Library path and static library
LIB = lib/libbotan-3.a

# Output executable
TARGET = cmac

# Source file
SRC = cmac.cpp

# Default target
all: $(TARGET)

# Build rule
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LIB)

# Clean
clean:
	rm -f $(TARGET)

.PHONY: all clean

