# Contributing to Nemue

Thank you for your interest in contributing to Nemue! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- Git
- Linux or macOS (Windows support planned)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/supunhg/Nemue.git
cd Nemue

# Build the project
cargo build

# Run tests
cargo test

# Build release binary
cargo build --release
```

### Project Structure

```
nemue/
├── src/              # Rust source code
├── scripts/          # Lua scripts (NSE-compatible)
├── tests/            # Integration tests
├── benches/          # Benchmarks
├── docs/             # Documentation
└── debian/           # Debian packaging files
```

## Testing Guidelines

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Writing Tests

- Add unit tests in the same file as the code being tested
- Add integration tests in the `tests/` directory
- Ensure all tests pass before submitting a PR
- Aim for high test coverage on new features

## Code Style Guidelines

### Rust Code

- Follow the official Rust style guide
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes
- Document public APIs with doc comments
- Use meaningful variable and function names
- Handle errors properly using `anyhow` or `thiserror`

### Lua Scripts

- Follow NSE script conventions
- Include proper error handling
- Add documentation comments at the top of each script
- Use consistent naming conventions

### Formatting

```bash
# Format Rust code
cargo fmt

# Check for linting issues
cargo clippy
```

## Pull Request Process

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** following the code style guidelines
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Run all tests** and ensure they pass
6. **Submit a pull request** with a clear description

### PR Description

Include in your PR description:

- What the change does
- Why the change is needed
- Any breaking changes
- Related issues (if applicable)

### Review Process

- All PRs require review before merging
- Address review comments promptly
- Keep PRs focused on a single change
- Rebase on main if needed

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Include relevant logs and error messages
- Specify your OS and Rust version

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
