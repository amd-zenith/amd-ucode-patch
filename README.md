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

Installing the package provides the following command line tools. Run any tool
with `--help` for usage details.

| Tool                   | Description                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------- |
| `amd_ucode_patch_info` | Inspect patch files and print their decoded header fields as a table (text, Markdown or CSV). |
| `amd_ucode_patch_sign` | Inspect, verify (`verify`) and re-sign (`resign`) patch signatures.                           |

## Library usage

The package can also be used programmatically:

```python
from pathlib import Path
from amd_ucode_patch.parse import ucode_patch_parse

patch = ucode_patch_parse(Path("firmware.bin"))
print(patch.header.patch_level)
print(f"{patch.header.cpuid.cpuid_signature:08X}")
```
