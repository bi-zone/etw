#!/usr/bin/env bash

export GOOS=windows
export CGO_ENABLED=1

GOARCH=$(go env GOARCH)
case "${GOARCH}" in
amd64)
  export CC=x86_64-w64-mingw32-gcc
  ;;
386)
  export CC=i686-w64-mingw32-gcc
  ;;
*)
  echo "Unsupported GOARCH==${GOARCH}"
  exit 1
  ;;
esac
