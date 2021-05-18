# `signal-protocol`

This demonstrates specifications for certain functions from
[`libsignal-protocol-c`](https://github.com/signalapp/libsignal-protocol-c),
a C implementation of the [Signal Protocol](https://en.wikipedia.org/wiki/Signal_Protocol).
This includes both a SAWScript implementation (under the `saw/` directory) as well as a
Python implementation (under the `python/` directory).

The Python code in particular is described in more detail in
[this blog post](https://galois.com/blog/2021/05/of-protocols-and-pythons/).

# Dependencies

In addition to the dependencies mentioned in the [top-level `README`](../../README.md),
the following additional dependencies are required, regardless of whether you are
running the SAWScript or Python demo:

* [CMake](https://cmake.org/)
* [WLLVM](https://github.com/travitch/whole-program-llvm)

If you are running the Python demo, you will also need:

* [Python](https://www.python.org/) (3.8 or later)
* [Poetry](https://python-poetry.org/)

# SAWScript version

To run the SAWScript demo, run:

```
$ make
```

# Python version

To run the Python demo, run:

```
$ make all-python
```
