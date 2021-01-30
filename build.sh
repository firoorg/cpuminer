#!/bin/bash

if [ "$OS" = "Windows_NT" ]; then
    ./mingw64.sh
    exit 0
fi

# Linux build

# Clean the directory
make clean || echo clean

# remove config status
rm -f config.status

# Run autogen
sh autogen.sh || echo done

# Configure build
./configure --with-crypto --with-curl CFLAGS="-O2 -flto -fuse-linker-plugin -ftree-loop-if-convert-stores -march=native -DUSE_ASM -pg"

# Build
make -j$(nproc --ignore=2)

strip -s cpuminer
