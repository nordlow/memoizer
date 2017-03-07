GEN_TABLES=./gen_tables.py
LINUX_SRC=/usr/include/asm

CXX=g++
CC=gcc

CFLAGS=-Wall -Wextra -O2 -g
CXXFLAGS=$(CFLAGS) -std=c++17

LDFLAGS=-lssl -lcrypto -lz		# -s	# SHA hashing support

all: memoized

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)

memoized: memoized.cpp syscalls.h syscallents.h Makefile zpipe.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $< zpipe.o
zpipe.o: zpipe.c Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

memoized_d: memoized.d Makefile
	dmd $(CXXFLAGS) $(LDFLAGS) -o $@ memoized.d

clean:
	$(RM) syscallents.h memoized memoized_cxx memoized_d
