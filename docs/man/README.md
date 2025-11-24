# Nemue Man Pages

This directory contains Unix-style manual pages for Nemue commands.

## Installation

```bash
# Copy man pages to system directory (requires root)
sudo mkdir -p /usr/local/share/man/man1
sudo cp nemue.1 nemue-scan.1 nemue-fuzz.1 /usr/local/share/man/man1/
sudo mandb
```

## Viewing Man Pages

```bash
# View main manual
man nemue

# View scan command manual
man nemue-scan

# View fuzz command manual
man nemue-fuzz
```

## Viewing Without Installation

```bash
# From the Nemue root directory
man docs/man/nemue.1
man docs/man/nemue-scan.1
man docs/man/nemue-fuzz.1
```

## Available Pages

- **nemue.1** - Main manual page (overview, commands, options)
- **nemue-scan.1** - Network scanning manual (all scan options and examples)
- **nemue-fuzz.1** - Web fuzzing manual (fuzzing modes, wordlists, examples)

## Format

Man pages are written in groff/roff format, following Unix manual page conventions.
