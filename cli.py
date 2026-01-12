#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CLI entrypoint (kept for compatibility)."""

from __future__ import annotations

import argparse
from pathlib import Path

from elfrender.model import DEFAULT_IGNORE_BASE_PATHS, generate_report


def main():
    parser = argparse.ArgumentParser(description="Generate ELF/DWARF symbol size report")
    parser.add_argument("elf", help="Path to ELF")
    parser.add_argument("out_dir", nargs="?", default=".", help="Output directory")
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        help="Ignore base path (repeatable). If not provided, defaults are used.",
    )
    args = parser.parse_args()

    ignore_paths = [Path(p) for p in args.ignore] if args.ignore else list(DEFAULT_IGNORE_BASE_PATHS)
    result = generate_report(args.elf, args.out_dir, ignore_base_paths=ignore_paths)
    print(f"[+] Generated: {result.symbols_json}")
    print(f"[+] Open: {result.report_html}")


if __name__ == "__main__":
    main()
