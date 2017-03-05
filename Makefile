GEN_TABLES=./gen_tables.py
LINUX_SRC=/usr/include/asm

CXX=g++
CXXFLAGS=-Wall -Wextra -O2 -std=c++17 -g
LDFLAGS=-lssl -lcrypto # -s	# SHA hashing support

all: memoized

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)

memoized: memoized.cpp syscalls.h syscallents.h Makefile
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

memoized_d: memoized.d Makefile
	dmd $(CXXFLAGS) $(LDFLAGS) -o $@ memoized.d

clean:
	$(RM) syscallents.h memoized memoized_cxx memoized_d
