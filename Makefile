CC=g++
CFLAGS=-c -std=c++17 -Wall -Wextra -Wshadow -Wold-style-cast -fstack-protector -O0 -g
LDFLAGS=-lssl -lcrypto -O0 -g

SOURCES=$(wildcard *.cpp)
DEPS=$(SOURCES:%.cpp=build/%.d)
OBJECTS=$(SOURCES:%.cpp=build/%.o)
EXECUTABLE=test


all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

build/%.o: %.cpp
	@mkdir -p $(@D)
	$(CC) -MMD $(CFLAGS) $< -o $@

-include $(DEPS)

clean:
	-rm -r build/*

