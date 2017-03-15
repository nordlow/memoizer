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

Enables
=======

- caching
- detection of process flow: consumer inputs of producer of outputs
- safe parallelization
- immutable persistent storage of inputs and outputs
- detect cyclic dependencies (inputs same as outputs)

Features
=========

- Tracks reads (inputs)
- Trackes writes and their potential renames (output)
- Tracks stats and access
- Intercepts calls to stat() to peek at its modification time (`st_mtime`)

Planned Features
================

Assert project-relative reads from only persistent inputs, that is non-modified
files with Git status up-to-date:

- `--assert-persistent-relative-reads`

Assert read and writes from specific set of directories:

- `--only-reads-from=DIRS`
- `--only-writes-to=DIRS`

Environment control:

- `--empty-default-env`, `--no-default-env`
- `--set-env='PATH=PATH_VALUE:CC=CC_VALUE'`
- `--use-existing-env-vars=VAR1,VAR2`
