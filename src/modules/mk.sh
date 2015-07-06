#!/bin/sh

gcc -Wall -O2 -o loader loader.c -ldl
gcc -fPIC -Wall -g -c libhello.c
gcc -g -shared -Wl,-soname,libhello.so.0 -o libhello.so.0.0 libhello.o
