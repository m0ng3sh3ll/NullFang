#!/bin/bash
# GoReleaser build script - Versão otimizada

echo "Creating builds directory..."
mkdir -p builds

platforms=(
    "windows/amd64"
    "windows/arm64"
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

for platform in "${platforms[@]}"
do
    GOOS=$(echo $platform | cut -f1 -d'/')
    GOARCH=$(echo $platform | cut -f2 -d'/')

    output_name="nullfang-$GOOS-$GOARCH"
    if [ "$GOOS" = "windows" ]; then
        output_name+=".exe"
    fi

    echo "Building for $GOOS/$GOARCH..."

    env GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-s -w" \
        -trimpath \
        -o "builds/$output_name" \
        main.go

    if [ $? -ne 0 ]; then
        echo "An error occurred while building for $GOOS/$GOARCH."
        exit 1
    fi
done

echo "All builds completed successfully!"
ls -lh builds/


echo "Compressing binaries..."
for file in builds/*; do
    if [ -f "$file" ]; then
        gzip -k "$file"
        echo "Compressed: $file -> $file.gz"
    fi
done

echo "Build and compression completed!"
ls -lh builds/