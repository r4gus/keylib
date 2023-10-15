from setuptools import setup, Extension
from Cython.Build import cythonize

uhid_module = Extension(
    "uhid",
    sources=["./uhidmodule.pyx"],
    include_dirs=["../../zig-out/include"],
    libraries=["uhid"],
    library_dirs=["../../zig-out/lib"],
)

setup(
    ext_modules = cythonize(uhid_module),
)
