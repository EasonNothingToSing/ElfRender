#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Model layer: parse ELF/DWARF and generate a symbols size report.

This module is intentionally UI-agnostic so it can be used by both CLI and GUI.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


DEFAULT_IGNORE_BASE_PATHS: list[Path] = [
    Path(r"D:\\Job\\ListenAI\\project\\ListenAI_Pro"),
    Path(r"\\\\workspace"),
    Path(r"D:\\vegah_slave\\listenai_rtos"),
]


def _lookup_cu_by_addr(dwarfinfo, addr: int):
    """Map an instruction address to a CU using .debug_aranges.

    Returns:
        (cu, lineprog) or (None, None)
    """

    try:
        aranges = dwarfinfo.get_aranges()
        cu = aranges.find(addr)
        if cu is None:
            return None, None
        lineprog = dwarfinfo.line_program_for_CU(cu)
        return cu, lineprog
    except Exception:
        return None, None


def _file_from_lineprog(lineprog, addr: int) -> str | None:
    """Try to resolve a file entry name for a given address from a CU line program."""

    if not lineprog:
        return None

    file_entries = lineprog["file_entry"] if "file_entry" in lineprog.header else None

    prev_state = None
    for entry in lineprog.get_entries():
        if entry.state is None:
            continue

        state = entry.state
        if prev_state and prev_state.end_sequence:
            prev_state = state
            continue

        if prev_state and prev_state.address <= addr < state.address:
            if file_entries:
                idx = (prev_state.file or 1) - 1  # DWARF file index starts from 1
                if 0 <= idx < len(file_entries):
                    fe = file_entries[idx]
                    try:
                        return fe.name.decode("utf-8", errors="ignore")
                    except Exception:
                        return str(fe.name)
            return None
        prev_state = state

    if prev_state and file_entries:
        idx = (prev_state.file or 1) - 1
        if 0 <= idx < len(file_entries):
            fe = file_entries[idx]
            try:
                return fe.name.decode("utf-8", errors="ignore")
            except Exception:
                return str(fe.name)
    return None


def _comp_dir_from_cu(cu) -> str:
    """Return the compilation directory from a CU."""

    try:
        cu_die = cu.get_top_DIE()
        if cu_die and "DW_AT_comp_dir" in cu_die.attributes:
            v = cu_die.attributes["DW_AT_comp_dir"].value
            return v.decode("utf-8", errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v)
    except Exception:
        return ""
    return ""


def _parse_dwarf_items(elffile: ELFFile) -> list[dict[str, Any]]:
    """Collect symbols from DWARF DIEs."""

    results: list[dict[str, Any]] = []
    dwarfinfo = elffile.get_dwarf_info()

    for cu in dwarfinfo.iter_CUs():
        lineprog = dwarfinfo.line_program_for_CU(cu)
        file_entries = lineprog["file_entry"] if lineprog else None
        comp_dir = _comp_dir_from_cu(cu)

        for die in cu.iter_DIEs():
            if die.tag not in ("DW_TAG_subprogram", "DW_TAG_variable", "DW_TAG_member"):
                continue

            lowpc = die.attributes.get("DW_AT_low_pc")
            highpc = die.attributes.get("DW_AT_high_pc")
            if lowpc and highpc:
                lowpc_val = int(lowpc.value)
                highpc_attr = highpc
                if describe_form_class(highpc_attr.form) == "address":
                    highpc_val = int(highpc_attr.value)
                else:
                    highpc_val = lowpc_val + int(highpc_attr.value)
                size = max(0, int(highpc_val - lowpc_val))
            else:
                lowpc_val, size = None, 0

            srcfile = "<unknown>"
            if "DW_AT_decl_file" in die.attributes and file_entries:
                idx = die.attributes["DW_AT_decl_file"].value
                if 1 <= idx <= len(file_entries):
                    entry = file_entries[idx - 1]
                    try:
                        srcfile = entry.name.decode("utf-8", errors="ignore")
                    except Exception:
                        srcfile = str(entry.name)

            name_attr = die.attributes.get("DW_AT_name")
            if name_attr:
                try:
                    name = name_attr.value.decode("utf-8", errors="ignore")
                except Exception:
                    name = str(name_attr.value)
            else:
                name = "<unnamed>"

            srcfile = (srcfile or "<unknown>").replace("\\\\", "/").lstrip("./") or "<unknown>"
            results.append(
                {
                    "name": name or "<unnamed>",
                    "srcfile": srcfile,
                    "size": size,
                    "dir": comp_dir or "",
                    "addr": lowpc_val,
                    "from": "DWARF",
                }
            )

    return results


def _parse_elf_symbols(elffile: ELFFile) -> list[dict[str, Any]]:
    """Collect symbols from .symtab/.dynsym."""

    syms: list[dict[str, Any]] = []
    for sec in elffile.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue

        for sym in sec.iter_symbols():
            try:
                name = sym.name or ""
                size = int(sym["st_size"] or 0)
                st_info = sym["st_info"]["type"]
                addr = int(sym["st_value"] or 0)
                shndx = sym["st_shndx"]
                section_name = None
                if isinstance(shndx, int) and 0 <= shndx < elffile.num_sections():
                    section_name = elffile.get_section(shndx).name
            except Exception:
                continue

            if size <= 0:
                continue
            if st_info not in ("STT_FUNC", "STT_OBJECT"):
                # Keep other types if you want; currently filtered by size only.
                pass

            syms.append(
                {
                    "name": name or "<unnamed>",
                    "addr": addr,
                    "size": size,
                    "section": section_name or "<no-section>",
                }
            )
    return syms


def _merge_results_with_elf(results: list[dict[str, Any]], elffile: ELFFile) -> list[dict[str, Any]]:
    """Merge ELF symbols into DWARF results and backfill paths when possible."""

    out = list(results)
    dwarfinfo = elffile.get_dwarf_info() if elffile.has_dwarf_info() else None

    seen: set[tuple[int, int, str]] = set()
    for r in results:
        key = (int(r.get("addr") or 0), int(r.get("size") or 0), str(r.get("name") or ""))
        seen.add(key)

    for e in _parse_elf_symbols(elffile):
        key = (int(e["addr"] or 0), int(e["size"] or 0), str(e["name"] or ""))
        if key in seen:
            continue

        srcfile, comp_dir = "<unknown>", ""
        if dwarfinfo and e["addr"]:
            cu, lineprog = _lookup_cu_by_addr(dwarfinfo, int(e["addr"]))
            if cu:
                comp_dir = _comp_dir_from_cu(cu) or ""
                fn = _file_from_lineprog(lineprog, int(e["addr"]))
                if fn:
                    srcfile = fn.replace("\\\\", "/").lstrip("./") or "<unknown>"

        out.append(
            {
                "name": e["name"] or "<unnamed>",
                "srcfile": srcfile,
                "size": int(e["size"] or 0),
                "dir": comp_dir or "",
                "addr": int(e["addr"] or 0),
                "from": "ELF",
                "section": e.get("section") or "<no-section>",
            }
        )
        seen.add(key)

    return out


def parse_elf_and_dwarf(elf_path: str | Path) -> list[dict[str, Any]]:
    """Parse DWARF + ELF symbol tables and return merged records."""

    elf_path = str(elf_path)
    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)
        dwarf_results = _parse_dwarf_items(elffile) if elffile.has_dwarf_info() else []
        return _merge_results_with_elf(dwarf_results, elffile)


def build_tree(
    parsed: Iterable[dict[str, Any]],
    ignore_base_paths: list[Path] | None = None,
):
    """Build a directory->file->symbol aggregation tree."""

    ignore_base_paths = ignore_base_paths or list(DEFAULT_IGNORE_BASE_PATHS)
    tree: dict[str, Any] = {}

    for rec in parsed:
        comp_dir = str(rec.get("dir") or "")
        srcfile = str(rec.get("srcfile") or "<unknown>")
        name = str(rec.get("name") or "<unnamed>")
        size = int(rec.get("size") or 0)
        origin = str(rec.get("from") or "DWARF")
        section = rec.get("section")

        if size <= 0:
            continue

        if origin == "ELF" and (not comp_dir or srcfile == "<unknown>"):
            bucket_dir = "[NO_DWARF]"
            bucket_sec = str(section or "<no-section>")
            node = tree.setdefault(bucket_dir, {"__type__": "dir", "__children__": {}, "__size__": 0})[
                "__children__"
            ]
            node = node.setdefault(bucket_sec, {"__type__": "dir", "__children__": {}, "__size__": 0})[
                "__children__"
            ]
            file_node = node.setdefault("<elf-symtab>", {"__type__": "file", "__symbols__": [], "__size__": 0})
            file_node["__symbols__"].append({"name": name, "size": size})
            file_node["__size__"] += size
            continue

        parts: tuple[str, ...]
        if comp_dir:
            comp_path = Path(comp_dir)
            rel_parts = None
            for base in ignore_base_paths:
                try:
                    rel_parts = comp_path.relative_to(base).parts
                    break
                except Exception:
                    continue
            parts = rel_parts if rel_parts is not None else comp_path.parts
        else:
            parts = tuple()

        srcfile = srcfile.replace("\\\\", "/").lstrip("./") or "<unknown>"

        node = tree
        for part in parts:
            if part in ("", ".", "/"):
                continue
            node = node.setdefault(part, {"__type__": "dir", "__children__": {}, "__size__": 0})["__children__"]

        file_node = node.setdefault(srcfile, {"__type__": "file", "__symbols__": [], "__size__": 0})
        file_node["__symbols__"].append({"name": name, "size": size})
        file_node["__size__"] += size

    def calc_dir_size(node: dict[str, Any]):
        total = 0
        dir_cnt = 0
        file_cnt = 0
        sym_cnt = 0
        for _, val in node.items():
            if val["__type__"] == "dir":
                dsz, ddir, dfile, dsym = calc_dir_size(val["__children__"])
                val["__size__"] = dsz
                total += dsz
                dir_cnt += 1 + ddir
                file_cnt += dfile
                sym_cnt += dsym
            else:
                total += val["__size__"]
                file_cnt += 1
                sym_cnt += len(val["__symbols__"])
        return total, dir_cnt, file_cnt, sym_cnt

    total_size, dir_count, file_count, symbol_count = calc_dir_size(tree)
    stats = {
        "total_size": total_size,
        "dir_count": dir_count,
        "file_count": file_count,
        "symbol_count": symbol_count,
    }
    return tree, stats


def write_json(tree: dict[str, Any], stats: dict[str, Any], elf_path: str | Path, out_json: str | Path):
    payload = {
        "tree": tree,
        "stats": stats,
        "meta": {
            "elf": Path(elf_path).name,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
    Path(out_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass(frozen=True)
class ReportResult:
    output_dir: Path
    symbols_json: Path
    report_html: Path


def generate_report(
    elf_path: str | Path,
    output_dir: str | Path,
    ignore_base_paths: list[Path] | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
    web_assets_dir: str | Path | None = None,
) -> ReportResult:
    """Generate symbols.json and copy the static report UI into output_dir."""

    def progress(pct: int, msg: str):
        if progress_cb:
            try:
                progress_cb(int(pct), str(msg))
            except Exception:
                pass

    elf_path = Path(elf_path)
    if not elf_path.exists():
        raise FileNotFoundError(f"ELF not found: {elf_path}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    progress(5, "Parsing ELF/DWARF…")
    parsed = parse_elf_and_dwarf(elf_path)

    progress(65, "Building aggregation tree…")
    tree, stats = build_tree(parsed, ignore_base_paths=ignore_base_paths)

    progress(80, "Writing symbols.json…")
    symbols_json = out_dir / "symbols.json"
    write_json(tree, stats, elf_path, out_json=symbols_json)

    progress(90, "Copying report assets…")
    assets_src = Path(web_assets_dir) if web_assets_dir else (Path(__file__).resolve().parents[1] / "web")
    if not assets_src.exists():
        raise FileNotFoundError(f"Report assets directory not found: {assets_src}")

    shutil.copytree(str(assets_src), str(out_dir), dirs_exist_ok=True)
    report_html = out_dir / "symbols.html"

    progress(100, "Done")
    return ReportResult(output_dir=out_dir, symbols_json=symbols_json, report_html=report_html)
