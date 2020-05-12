#!/usr/bin/env bash

export GOOS=windows
export CGO_ENABLED=1

case "${GOARCH}" in
x64)
  export CC=x86_64-w64-mingw32-gcc
  ;;
x86)
  export CC=i686-w64-mingw32-gcc
  ;;
esac
