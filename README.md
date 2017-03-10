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

Planned Features
================

Assert project-relative reads from only persistent inputs, that is non-modified
files with Git status up-to-date:

- `--assert-only-persistent-reads`

Assert read and writes from specific set of directories:

- `--only-reads-from=DIRS`
- `--only-writes-to=DIRS`

Environment control:

- `--skip-env`, `--no-env`
- `--set-env=...`
- `--use-env-vars=PATH,..`
