# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Project scaffold: packaging, CI, `ghostrules version`.
- Core engine: models, Unicode utilities, target discovery, config loading, scanner pipeline
  (rule registry, suppressions, decoded hidden-text pass).
- Rules GR001-GR006: Unicode tag characters, bidi controls, zero-width characters, variation-selector
  steganography, hidden HTML comments, mixed-script homoglyphs.
- `scripts/make_fixtures.py` generating reproducible, defanged fixtures.
