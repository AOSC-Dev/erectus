#!/bin/bash -e
clang -Oz shims.c -march=loongarch64 --target=loongarch64-linux-gnu -ffunction-sections -fdata-sections -c -o shims.o
