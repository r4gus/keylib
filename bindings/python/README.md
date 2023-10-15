# Python3 bindings

Currently you have to compile and link the Python3 modules using cpython.

1. make sure you have Python3 and [cython](https://cython.org/) installed.
2. build the `keylib` and `uhid` libraries with optimization (e.g. `zig build -Doptimize=ReleaseSmall`)
3. run `python3 setup.py build_ext --inplace` to build the python modules.
