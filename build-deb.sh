#!/bin/bash
#
# Nemue Debian Package Builder
# This script builds a .deb package for easy installation
#

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  Nemue Debian Package Builder"
echo "════════════════════════════════════════════════════════════════"
echo

# Check if required tools are installed
check_requirements() {
    echo "Checking requirements..."
    
    if ! command -v dpkg-buildpackage &> /dev/null; then
        echo "Error: dpkg-buildpackage not found. Please install:"
        echo "  sudo apt-get install dpkg-dev"
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        echo "Error: cargo not found. Please install Rust:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
    
    echo "✓ All requirements satisfied"
    echo
}

# Clean previous builds
clean_build() {
    echo "Cleaning previous builds..."
    if [ -d "debian/nemue" ]; then
        rm -rf debian/nemue
    fi
    if [ -d "debian/.debhelper" ]; then
        rm -rf debian/.debhelper
    fi
    # Remove any .deb files in parent directory
    rm -f ../*.deb ../*.buildinfo ../*.changes
    echo "✓ Clean complete"
    echo
}

# Build the package
build_package() {
    echo "Building Debian package..."
    echo "This may take several minutes..."
    echo
    
    # Build without signing (for local use)
    dpkg-buildpackage -us -uc -b
    
    echo
    echo "✓ Build complete"
    echo
}

# Show results
show_results() {
    echo "════════════════════════════════════════════════════════════════"
    echo "  Build Results"
    echo "════════════════════════════════════════════════════════════════"
    echo
    
    if [ -f "../nemue_0.1.0-1_amd64.deb" ]; then
        echo "✓ Package created successfully!"
        echo
        echo "Package location: ../nemue_0.1.0-1_amd64.deb"
        echo "Package size: $(du -h ../nemue_0.1.0-1_amd64.deb | cut -f1)"
        echo
        echo "To install:"
        echo "  sudo dpkg -i ../nemue_0.1.0-1_amd64.deb"
        echo
        echo "To uninstall:"
        echo "  sudo dpkg -r nemue"
        echo
        echo "To view package contents:"
        echo "  dpkg -c ../nemue_0.1.0-1_amd64.deb"
        echo
        echo "To view package info:"
        echo "  dpkg -I ../nemue_0.1.0-1_amd64.deb"
        echo
    else
        echo "✗ Package build failed"
        exit 1
    fi
}

# Main execution
main() {
    check_requirements
    clean_build
    build_package
    show_results
}

main "$@"
