#!/bin/bash
set -e

echo "Building go-secrets with runtime/secret support..."
echo ""
echo "Checking for go1.26rc1..."

if ! command -v go1.26rc1 &> /dev/null; then
    echo "go1.26rc1 not found. Installing..."
    go install golang.org/dl/go1.26rc1@latest
    go1.26rc1 download
fi

echo "Building with GOEXPERIMENT=runtimesecret..."
GOEXPERIMENT=runtimesecret go1.26rc1 build -o secrets ./cmd/secrets

echo ""
echo "Build complete! Binary created: ./secrets"
echo ""
echo "To install system-wide, run:"
echo "  sudo mv secrets /usr/local/bin/"
echo ""
echo "Note: runtime/secret memory clearing is only active on linux/amd64 and linux/arm64"
echo "      On other platforms, the binary will work but without enhanced memory protection"
