#!/bin/bash
#
# Simple .deb package builder (without dpkg-buildpackage)
# For systems without full Debian build tools
#

set -e

VERSION="0.1.0"
ARCH="amd64"
PKG_NAME="nemue_${VERSION}-1_${ARCH}"
BUILD_DIR="build/${PKG_NAME}"

echo "════════════════════════════════════════════════════════════════"
echo "  Nemue Simple Package Builder"
echo "════════════════════════════════════════════════════════════════"
echo

# Build the release binary
echo "Building release binary..."
cargo build --release --locked
echo "✓ Binary built"
echo

# Create package structure
echo "Creating package structure..."
rm -rf build
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/bin"
mkdir -p "${BUILD_DIR}/usr/share/nemue/scripts"
mkdir -p "${BUILD_DIR}/usr/share/doc/nemue"
mkdir -p "${BUILD_DIR}/usr/share/man/man1"

# Copy binary
cp target/release/nemue "${BUILD_DIR}/usr/bin/"
chmod 755 "${BUILD_DIR}/usr/bin/nemue"

# Copy scripts
cp -r scripts/* "${BUILD_DIR}/usr/share/nemue/scripts/"

# Copy documentation
cp README.md "${BUILD_DIR}/usr/share/doc/nemue/"
cp QUICK_START.md "${BUILD_DIR}/usr/share/doc/nemue/"
cp USAGE.md "${BUILD_DIR}/usr/share/doc/nemue/"
cp ARCHITECTURE.md "${BUILD_DIR}/usr/share/doc/nemue/"
gzip -9 -n -c debian/changelog > "${BUILD_DIR}/usr/share/doc/nemue/changelog.gz"

echo "✓ Files copied"
echo

# Create control file
cat > "${BUILD_DIR}/DEBIAN/control" << EOF
Package: nemue
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.31)
Maintainer: Nemue Team <nemue@security.dev>
Description: Advanced security testing framework
 Nemue is a high-performance network security testing framework built in Rust,
 featuring comprehensive scanning capabilities, service detection, OS
 fingerprinting, and an extensible NSE-compatible scripting engine.
 .
 Key features:
  * High-performance async scanning (1000+ packets/second)
  * Multiple scan types (SYN, Connect, UDP, etc.)
  * Advanced service version detection with 1000+ signatures
  * TCP/IP stack OS fingerprinting
  * 59 NSE-compatible Lua scripts
  * Multiple output formats (Normal, XML, JSON, Grepable)
  * Parallel port scanning with timing controls
Homepage: https://github.com/supunhg/Nemue
EOF

# Create postinst script
cat > "${BUILD_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    echo "Nemue has been installed successfully!"
    echo "Run 'nemue --help' to get started"
fi

#DEBHELPER#

exit 0
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

# Create prerm script
cat > "${BUILD_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ]; then
    echo "Removing Nemue..."
fi

#DEBHELPER#

exit 0
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

echo "✓ Control files created"
echo

# Build the package
echo "Building .deb package..."
dpkg-deb --build --root-owner-group "${BUILD_DIR}"
mv "build/${PKG_NAME}.deb" .
echo "✓ Package built"
echo

# Show results
echo "════════════════════════════════════════════════════════════════"
echo "  Build Complete!"
echo "════════════════════════════════════════════════════════════════"
echo
echo "Package: ${PKG_NAME}.deb"
echo "Size: $(du -h ${PKG_NAME}.deb | cut -f1)"
echo
echo "To install:"
echo "  sudo dpkg -i ${PKG_NAME}.deb"
echo "  sudo apt-get install -f  # if dependencies missing"
echo
echo "To uninstall:"
echo "  sudo dpkg -r nemue"
echo
echo "To view contents:"
echo "  dpkg -c ${PKG_NAME}.deb"
echo
echo "To view package info:"
echo "  dpkg -I ${PKG_NAME}.deb"
echo
