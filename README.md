memoizer
========

Process call memoizer similar to memoize.py but written in C++11 with direct
calls to `ptrace` for maximum performance. Uncached run-time overhead is ca
10 percent.

Inspired by https://github.com/nelhage/ministrace/ and
http://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

Usage
=====

```memoized <program> <program args>```
