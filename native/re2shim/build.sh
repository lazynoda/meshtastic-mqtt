#!/bin/sh
# Builds libre2shim.so into the directory given as the first argument, against the RE2 of this system
# (Debian/Ubuntu: apt-get install g++ libre2-dev). The Dockerfile runs it; see docs/operations.md to
# run the tests outside Docker.
set -eu
out="${1:?usage: build.sh <output directory>}"
mkdir -p "$out"
g++ -O2 -std=c++17 -fPIC -shared -fvisibility=hidden -Wall -Wextra \
    -o "$out/libre2shim.so" "$(dirname "$0")/re2shim.cc" -lre2
