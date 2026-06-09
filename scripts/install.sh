#!/bin/bash
# Nemue installation script
# Detects OS and installs appropriate binary

set -e

REPO="supunhg/Nemue"
BINARY_NAME="nemue"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="macos";;
        *)          error "Unsupported OS: $(uname -s)";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64*)    ARCH="x86_64";;
        aarch64*)   ARCH="aarch64";;
        arm64*)     ARCH="aarch64";;
        *)          error "Unsupported architecture: $(uname -m)";;
    esac
}

check_dependencies() {
    if ! command -v curl &> /dev/null; then
        error "curl is required. Please install curl first."
    fi
}

install_binary() {
    info "Downloading Nemue for ${OS}-${ARCH}..."
    
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    
    if curl -fsSL "${DOWNLOAD_URL}" -o "/tmp/${BINARY_NAME}"; then
        chmod +x "/tmp/${BINARY_NAME}"
        
        if [ -w "${INSTALL_DIR}" ]; then
            mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        else
            warn "Need sudo privileges to install to ${INSTALL_DIR}"
            sudo mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        fi
        
        info "Nemue installed successfully to ${INSTALL_DIR}/${BINARY_NAME}"
    else
        error "Failed to download Nemue. Check your internet connection."
    fi
}

install_deb() {
    info "Installing via .deb package..."
    
    DEB_URL="https://github.com/${REPO}/releases/latest/download/nemue_amd64.deb"
    
    if curl -fsSL "${DEB_URL}" -o "/tmp/nemue.deb"; then
        if command -v dpkg &> /dev/null; then
            sudo dpkg -i "/tmp/nemue.deb"
            sudo apt-get install -f -y
        else
            error "dpkg not found. Use binary installation instead."
        fi
        rm -f "/tmp/nemue.deb"
        info "Nemue installed successfully via .deb package"
    else
        error "Failed to download .deb package."
    fi
}

install_from_source() {
    info "Building from source..."
    
    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo not found. Install Rust first: https://rustup.rs"
    fi
    
    TEMP_DIR=$(mktemp -d)
    git clone "https://github.com/${REPO}.git" "${TEMP_DIR}"
    cd "${TEMP_DIR}"
    cargo build --release
    
    if [ -w "${INSTALL_DIR}" ]; then
        cp target/release/${BINARY_NAME} "${INSTALL_DIR}/"
    else
        sudo cp target/release/${BINARY_NAME} "${INSTALL_DIR}/"
    fi
    
    rm -rf "${TEMP_DIR}"
    info "Nemue built and installed successfully"
}

show_help() {
    echo "Nemue Installation Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --binary    Install pre-built binary (default)"
    echo "  --deb       Install via .deb package (Debian/Ubuntu only)"
    echo "  --source    Build and install from source"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Install binary"
    echo "  $0 --deb        # Install .deb package"
    echo "  $0 --source     # Build from source"
}

main() {
    local method="binary"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --binary)   method="binary"; shift;;
            --deb)      method="deb"; shift;;
            --source)   method="source"; shift;;
            --help)     show_help; exit 0;;
            *)          error "Unknown option: $1";;
        esac
    done
    
    info "Installing Nemue..."
    
    detect_os
    detect_arch
    check_dependencies
    
    case ${method} in
        binary) install_binary;;
        deb)    install_deb;;
        source) install_from_source;;
    esac
    
    if command -v ${BINARY_NAME} &> /dev/null; then
        info "Installation complete! Run '${BINARY_NAME} --help' to get started."
    else
        warn "Installation complete but ${BINARY_NAME} not found in PATH."
        warn "You may need to add ${INSTALL_DIR} to your PATH."
    fi
}

main "$@"
