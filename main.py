#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from datetime import datetime
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.descriptions import describe_form_class

# 你的忽略前缀（保持不变）
IGNORE_BASE_PATHS = [
    Path(r"D:\\Job\\ListenAI\\project\\ListenAI_Pro"),
    Path(r"\\workspace"),
    Path(r"D:\\vegah_slave\\listenai_rtos"),
]

# ---------------- 工具函数：地址 -> (CU, lineprog) -> 源文件名、comp_dir ----------------
def _lookup_cu_by_addr(dwarfinfo, addr):
    """使用 .debug_aranges 将指令地址映射到某个 CU；失败则返回 (None, None)"""
    try:
        aranges = dwarfinfo.get_aranges()
        cu = aranges.find(addr)
        if cu is None:
            return None, None
        lineprog = dwarfinfo.line_program_for_CU(cu)
        return cu, lineprog
    except Exception:
        return None, None

def _file_from_lineprog(lineprog, addr):
    """
    给定 CU 的 line program 和地址，尝试找到对应的 file entry 名称。
    对于精确匹配，我们顺序执行 matrix（行表），找 state.address <= addr < next.address 的行。
    """
    if not lineprog:
        return None
    # 萃取 file entries（可能为空）
    file_entries = lineprog['file_entry'] if 'file_entry' in lineprog.header else None
    # 回放指令流
    prev_state = None
    for entry in lineprog.get_entries():
        if entry.state is None:
            continue
        state = entry.state
        if prev_state and prev_state.end_sequence:
            prev_state = state
            continue
        if prev_state and prev_state.address <= addr < state.address:
            # 命中 prev_state 所在行
            if file_entries:
                idx = (prev_state.file or 1) - 1  # DWARF file index 从 1 开始
                if 0 <= idx < len(file_entries):
                    fe = file_entries[idx]
                    try:
                        return fe.name.decode('utf-8', errors='ignore')
                    except Exception:
                        return str(fe.name)
            return None
        prev_state = state
    # 处理落到最后一段的情况
    if prev_state and file_entries:
        idx = (prev_state.file or 1) - 1
        if 0 <= idx < len(file_entries):
            fe = file_entries[idx]
            try:
                return fe.name.decode('utf-8', errors='ignore')
            except Exception:
                return str(fe.name)
    return None

def _comp_dir_from_cu(cu):
    """CU 的编译目录"""
    try:
        cu_die = cu.get_top_DIE()
        if cu_die and "DW_AT_comp_dir" in cu_die.attributes:
            v = cu_die.attributes["DW_AT_comp_dir"].value
            return v.decode('utf-8', errors='ignore') if isinstance(v, (bytes, bytearray)) else str(v)
    except Exception:
        pass
    return ""

# ---------------- 解析 DWARF（原有逻辑，稍做封装） ----------------
def _parse_dwarf_items(elffile):
    results = []
    dwarfinfo = elffile.get_dwarf_info()
    for cu in dwarfinfo.iter_CUs():
        lineprog = dwarfinfo.line_program_for_CU(cu)
        file_entries = lineprog['file_entry'] if lineprog else None
        comp_dir = _comp_dir_from_cu(cu)
        for die in cu.iter_DIEs():
            if die.tag not in ('DW_TAG_subprogram', 'DW_TAG_variable', 'DW_TAG_member'):
                continue
            # 尺寸
            lowpc = die.attributes.get('DW_AT_low_pc')
            highpc = die.attributes.get('DW_AT_high_pc')
            if lowpc and highpc:
                lowpc_val = lowpc.value
                highpc_attr = highpc
                if describe_form_class(highpc_attr.form) == 'address':
                    highpc_val = highpc_attr.value
                else:
                    highpc_val = lowpc_val + highpc_attr.value
                size = max(0, int(highpc_val - lowpc_val))
            else:
                lowpc_val, size = None, 0

            # 源文件
            srcfile = '<unknown>'
            if 'DW_AT_decl_file' in die.attributes and file_entries:
                idx = die.attributes['DW_AT_decl_file'].value
                if 1 <= idx <= len(file_entries):
                    entry = file_entries[idx - 1]
                    try:
                        srcfile = entry.name.decode('utf-8', errors='ignore')
                    except Exception:
                        srcfile = str(entry.name)

            # 名称
            name_attr = die.attributes.get('DW_AT_name')
            if name_attr:
                try:
                    name = name_attr.value.decode('utf-8', errors='ignore')
                except Exception:
                    name = str(name_attr.value)
            else:
                name = '<unnamed>'

            srcfile = (srcfile or '<unknown>').replace('\\', '/').lstrip('./') or '<unknown>'
            results.append({
                'name': name or '<unnamed>',
                'srcfile': srcfile,
                'size': size,
                'dir': comp_dir or '',
                'addr': lowpc_val,     # 额外带上起始地址，方便去重
                'from': 'DWARF',
            })
    return results

# ---------------- 解析 ELF 符号表并回填路径 ----------------
def _parse_elf_symbols(elffile):
    """
    从 .symtab/.dynsym 提取函数/对象符号（有 size 的），给出 name/addr/size/section。
    路径后续用 DWARF aranges+lineprog 回填。
    """
    syms = []
    for sec in elffile.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            try:
                name = sym.name or ''
                size = int(sym['st_size'] or 0)
                st_info = sym['st_info']['type']  # STT_FUNC/STT_OBJECT/...
                addr = sym['st_value'] or 0
                shndx = sym['st_shndx']
                section_name = None
                if isinstance(shndx, int) and 0 <= shndx < elffile.num_sections():
                    section_name = elffile.get_section(shndx).name
            except Exception:
                continue

            # 只收有体积且可能有意义的类型
            if size <= 0:
                continue
            if st_info not in ('STT_FUNC', 'STT_OBJECT'):
                # 你也可以放开其它类型
                pass

            syms.append({
                'name': name or '<unnamed>',
                'addr': addr,
                'size': size,
                'section': section_name or '<no-section>',
            })
    return syms

def _merge_results_with_elf(results, elffile):
    """
    把 ELF 符号表的条目加入到 results：
    - 若 DWARF 已有同 (addr,size,name) 的记录，则跳过；
    - 否则尝试通过 aranges+lineprog 回填 srcfile/dir；失败则放到 [NO_DWARF]/<section>。
    """
    out = list(results)
    dwarfinfo = elffile.get_dwarf_info() if elffile.has_dwarf_info() else None

    # 现有集合用于去重（优先保留有路径的 DWARF）
    seen = set()
    for r in results:
        key = (r.get('addr') or 0, r.get('size') or 0, r.get('name') or '')
        seen.add(key)

    elf_syms = _parse_elf_symbols(elffile)
    for e in elf_syms:
        key = (e['addr'] or 0, e['size'] or 0, e['name'] or '')
        if key in seen:
            continue

        srcfile, comp_dir = '<unknown>', ''
        if dwarfinfo and e['addr']:
            cu, lineprog = _lookup_cu_by_addr(dwarfinfo, e['addr'])
            if cu:
                comp_dir = _comp_dir_from_cu(cu) or ''
                fn = _file_from_lineprog(lineprog, e['addr'])
                if fn:
                    srcfile = fn.replace('\\', '/').lstrip('./') or '<unknown>'

        rec = {
            'name': e['name'] or '<unnamed>',
            'srcfile': srcfile,
            'size': int(e['size'] or 0),
            'dir': comp_dir or '',
            'addr': int(e['addr'] or 0),
            'from': 'ELF',
            'section': e.get('section') or '<no-section>',
        }

        # 若仍无路径，用“[NO_DWARF]/<section>” 作为归档目录（稍后 build_tree 时会处理）
        out.append(rec)
        seen.add(key)

    return out

# ---------------- 主解析：DWARF + ELF 合并 ----------------
def parse_elf_and_dwarf(elf_path: str):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            # 没有 DWARF 时，仍然返回 ELF 符号
            dwarf_results = []
        else:
            dwarf_results = _parse_dwarf_items(elffile)
        merged = _merge_results_with_elf(dwarf_results, elffile)
        return merged

# ---------------- 构建树（保留你的相对化规则；新增 [NO_DWARF] 兜底） ----------------
def build_tree(parsed):
    tree = {}

    for rec in parsed:
        comp_dir = rec.get('dir') or ''
        srcfile = rec.get('srcfile') or '<unknown>'
        name = rec.get('name') or '<unnamed>'
        size = int(rec.get('size') or 0)
        origin = rec.get('from') or 'DWARF'
        section = rec.get('section')

        if size <= 0:
            continue

        if origin == 'ELF' and (not comp_dir or srcfile == '<unknown>'):
            # 完全没有来源信息的 ELF 符号：放到兜底目录
            # [NO_DWARF]/<section 或 unknown>/<file-bucket>
            bucket_dir = "[NO_DWARF]"
            bucket_sec = section or "<no-section>"
            node = tree.setdefault(bucket_dir, {"__type__": "dir", "__children__": {}, "__size__": 0})["__children__"]
            node = node.setdefault(bucket_sec, {"__type__": "dir", "__children__": {}, "__size__": 0})["__children__"]
            # 以符号名作为“文件名”汇总，或者你也可以放进“<elf-symtab>”单一文件
            file_node = node.setdefault("<elf-symtab>", {"__type__": "file", "__symbols__": [], "__size__": 0})
            file_node["__symbols__"].append({"name": name, "size": size})
            file_node["__size__"] += size
            continue

        # 正常路径构造（与你现有逻辑一致）
        parts = None
        if comp_dir:
            comp_path = Path(comp_dir)
            for base in IGNORE_BASE_PATHS:
                try:
                    parts = comp_path.relative_to(base).parts
                    break
                except Exception:
                    continue
            if parts is None:
                parts = comp_path.parts
        else:
            parts = tuple()

        # 归一化 srcfile
        srcfile = srcfile.replace('\\', '/').lstrip('./') or '<unknown>'

        node = tree
        for part in parts:
            if part in ('', '.', '/'):
                continue
            node = node.setdefault(part, {"__type__": "dir", "__children__": {}, "__size__": 0})["__children__"]

        file_node = node.setdefault(srcfile, {"__type__": "file", "__symbols__": [], "__size__": 0})
        file_node["__symbols__"].append({"name": name, "size": size})
        file_node["__size__"] += size

    # 递归统计
    def calc_dir_size(node):
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

# ---------------- 导出 JSON ----------------
def write_json(tree, stats, elf_path, out_json="symbols.json"):
    payload = {
        "tree": tree,
        "stats": stats,
        "meta": {
            "elf": Path(elf_path).name,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
    Path(out_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON 已生成: {out_json}")

# ---------------- 主函数 ----------------
def main():
    import sys
    import shutil
    if len(sys.argv) < 2:
        print("用法: python3 gen_symbols_report.py <ELF路径> [输出目录]")
        raise SystemExit(1)

    elf_path = sys.argv[1]
    out_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    parsed = parse_elf_and_dwarf(elf_path)
    tree, stats = build_tree(parsed)
    write_json(tree, stats, elf_path, out_json=str(out_dir / "symbols.json"))
    shutil.copytree("./web", str(out_dir), dirs_exist_ok=True)
    print("请将 symbols.html / symbols.css / symbols.js 放在同一输出目录，使用浏览器打开 symbols.html。")

if __name__ == "__main__":
    main()
