GEN_TABLES=./gen_tables.py
LINUX_SRC=/usr/include/asm

CXX=g++
CXXFLAGS=-Wall -Wextra -O2 -g -std=c++11
LDFLAGS=-lssl -lcrypto

all: memoized

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)

memoized: memoized.cpp syscalls.h syscallents.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) syscallents.h memoized
