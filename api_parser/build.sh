#!/bin/bash
# build.sh - Build script for compiling to .so files

set -e

echo "Building api_parser with Cython..."

# Clean previous builds
rm -rf build/ dist/ *.egg-info
find . -name "*.so" -delete
find . -name "*.c" -delete

# Install build dependencies
pip install --upgrade pip setuptools wheel
pip install Cython

# Build
python3 setup.py build_ext --inplace

echo "Build complete! Compiled .so files are in:"
find . -name "*.so" -type f

# Optional: Remove .c files after build
# find . -name "*.c" -delete

