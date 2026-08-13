#!/bin/bash
set -e

echo "=== Building SR Linux SRLX Debian Package (.deb) ==="
docker run --rm -v "$PWD":/tmp -w /tmp goreleaser/nfpm pkg --packager deb --target /tmp/srlx_0.0.1.deb
echo "=== Successfully built srlx_0.0.1.deb ==="
