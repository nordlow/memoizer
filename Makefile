GEN_TABLES=./gen_tables.py
LINUX_SRC=/usr/include/asm

CXX=g++
CXXFLAGS=-Wall -Wextra -O2 -g -std=c++11
LDFLAGS=-lssl -lcrypto		# SHA hashing support

all: memoized_cxx

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)

memoized_cxx: memoized.cpp syscalls.h syscallents.h Makefile
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

memoized_d: memoized.d Makefile
	dmd $(CXXFLAGS) $(LDFLAGS) -o $@ memoized.d

clean:
	$(RM) syscallents.h memoized
