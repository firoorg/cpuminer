#!/bin/bash

# Checking Windows OS for extra configs.
if [ "$OS" = "Windows_NT" ]; then
    ./mingw64.sh
    exit 0
fi

# BE SURE TO RUN autoge.sh ONCE, OTHERWISE make clean WILL FAILS.

# Cleaning build sources
make clean # echo is too fast to be viewed
rm -f config.status

# Running autogen. Be sure to run it once if downloaded from git
sh autogen.sh

# Configuring the package
# -Ofast is just too much for what we need and gcc does not officially accept it as flag for "normal" purpouses
# -O2 is just fine.
sh configure --with-crypto --with-curl CFLAGS="-O2 -flto -fuse-linker-plugin -ftree-loop-if-convert-stores -DUSE_ASM -pg"

# Make the package
make -j$(nproc --all --ignore=2) # --all checks if there are more CPUs avaiable

# Stripping package
strip -s cpuminer
