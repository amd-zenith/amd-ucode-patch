# AMD Microcode Patch

[![Build](https://github.com/amd-zenith/amd-ucode-patch/actions/workflows/build.yml/badge.svg)](https://github.com/amd-zenith/amd-ucode-patch/actions/workflows/build.yml)
[![CodeQL](https://github.com/amd-zenith/amd-ucode-patch/actions/workflows/codeql.yml/badge.svg)](https://github.com/amd-zenith/amd-ucode-patch/actions/workflows/codeql.yml)
[![PyPI version](https://img.shields.io/pypi/v/amd-ucode-patch.svg)](https://pypi.org/project/amd-ucode-patch/)
[![Python versions](https://img.shields.io/pypi/pyversions/amd-ucode-patch.svg)](https://pypi.org/project/amd-ucode-patch/)
[![Snyk package health](https://img.shields.io/badge/Snyk-package%20health-4C4A73?logo=snyk&logoColor=white)](https://snyk.io/advisor/python/amd-ucode-patch)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/amd-zenith/amd-ucode-patch/badge)](https://scorecard.dev/viewer/?uri=github.com/amd-zenith/amd-ucode-patch)

A Python library for parsing and interpreting AMD microcode patch files.

## Installation

```bash
pip install amd-ucode-patch
```

## Command line tools

Installing the package provides the following command line tools.

### `amd_ucode_patch_info`

Inspect one or more AMD microcode patch files and print their header
information as a table.

```bash
amd_ucode_patch_info <files...> [-f {text,md,csv}]
```

Arguments:

- `files`: One or more patch files to inspect. Glob patterns (e.g. `*.bin` or `**/*.bin`) are expanded automatically.
- `-f`, `--format`: Output format. One of:
  - `text` (default): A table rendered for the terminal.
  - `md`: A Markdown table.
  - `csv`: Comma separated values.

For every patch file the following fields are reported: file name, date, update revision, loader ID, processor revision, CPUID, family, model, stepping, autorun, encrypted and body size.

## Library usage

The package can also be used programmatically:

```python
from amd_ucode_patch.parse import ucode_patch_parse

patch = ucode_patch_parse("firmware.bin")
print(patch.header.cpuid_str)
print(patch.header.update_revision)
```
