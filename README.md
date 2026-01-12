# ELF/DWARF Symbol Size Report

Generate an interactive, tree-view report of symbol sizes from ELF binaries—grouped by **directory → file → symbol**—with graceful handling for symbols that have **no DWARF path information**.

This project consists of:

* A **pywebview GUI** (`main.py`) that lets you pick an ELF, set ignore paths, generate the report, and open the viewer.
* A **CLI generator** (`cli.py`) that parses **DWARF** and **ELF symbol tables**, merges results, and writes `symbols.json`.
* A **pure static viewer** (`web/symbols.html`, `web/symbols.css`, `web/symbols.js`) that loads `symbols.json` and renders a collapsible tree.

---

## Features

* Parses **DWARF** DIEs (`DW_TAG_subprogram`, `DW_TAG_variable`, `DW_TAG_member`) for symbol size and source files.
* Augments with **ELF symbol tables** (`.symtab`/`.dynsym`) to include symbols **missing from DWARF**.
* Attempts **address→CU→line table** resolution to recover source file paths for ELF-only symbols.
* For remaining pathless symbols, places them under:

  ```
  [NO_DWARF]/
    <section-name>/
      <elf-symtab>   # aggregated file node for such symbols
  ```
* Clean, collapsible tree UI (directory → file → symbol) with **total sizes per node**.
* **Export**: download the raw `symbols.json` and a flattened `symbols.csv`.

---

## Requirements

* **Python**: 3.8+
* **pip**: `pyelftools`
* A target **ELF** binary compiled with or without DWARF (DWARF recommended for richer paths)

```bash
pip install pyelftools
```

No web server required: the UI is plain HTML/CSS/JS that opens in your browser.

---

## Quick Start

### GUI

```bash
python main.py
```

### CLI

1. **Generate data**

   ```bash
  python cli.py /path/to/your.elf outdir
   ```

   This produces:

   ```
   outdir/
     └─ symbols.json
   ```

2. **Copy the UI files** into the same directory:

   ```
   cp symbols.html symbols.css symbols.js outdir/
   ```

3. **Open the report**:

   * macOS: `open outdir/symbols.html`
   * Windows: `start outdir\symbols.html`
   * Linux: `xdg-open outdir/symbols.html`

---

## Output Overview

### `symbols.json`

Structured data consumed by the UI:

```json
{
  "tree": {
    "src": {
      "__type__": "dir",
      "__size__": 3200,
      "__children__": {
        "core": { "...": "..." },
        "drivers": { "...": "..." }
      }
    },
    "[NO_DWARF]": {
      "__type__": "dir",
      "__size__": 512,
      "__children__": {
        ".text": {
          "__type__": "dir",
          "__size__": 512,
          "__children__": {
            "<elf-symtab>": {
              "__type__": "file",
              "__size__": 512,
              "__symbols__": [
                { "name": "memcpy", "size": 256 },
                { "name": "startup_stub", "size": 256 }
              ]
            }
          }
        }
      }
    }
  },
  "stats": {
    "total_size": 3712,
    "dir_count": 4,
    "file_count": 7,
    "symbol_count": 143
  },
  "meta": { "elf": "your.elf", "generated_at": "YYYY-MM-DD HH:MM:SS" }
}
```

### UI (browser)

* Click 📁/**directories** or 📄/**files** to expand/collapse.
* **Export JSON** downloads the same `symbols.json`.
* **Export CSV** downloads a flat table with columns: `directory,file,symbol,size_bytes`.

---

## How It Works

1. **DWARF pass**

   * Iterates CUs and DIEs; extracts `DW_AT_low_pc`/`DW_AT_high_pc` to compute sizes.
   * Resolves `DW_AT_decl_file` via the CU line program to get per-symbol source file.
   * Tracks `DW_AT_comp_dir` (compile directory) to bucket files under their directories.
   * Normalizes paths and aggregates sizes by file and directory.

2. **ELF symbol pass**

   * Reads `.symtab`/`.dynsym` for symbols (e.g., `STT_FUNC`, `STT_OBJECT`) with nonzero size.
   * De-dupes against DWARF entries via `(address, size, name)`.

3. **Address-based path recovery**

   * For ELF-only symbols, attempts to map **address → CU** using `.debug_aranges`,
     then uses the CU’s **line program** to infer the **source file**.
   * If mapping fails, symbols are placed under:

     ```
     [NO_DWARF]/<section-name>/<elf-symtab>
     ```

4. **Tree building**

   * Compile directory (`DW_AT_comp_dir`) is made **relative** to a configurable ignore-list
     (see **Configuration** below).
   * Directory nodes keep a `__size__` sum of their subtree.

---

## Configuration

The generator supports **base path stripping** for friendlier directory trees:

```python
# in gen_symbols_report.py
IGNORE_BASE_PATHS = [
  Path(r"E:\Job\Listenai\ListenAI Project\listenai_rtos"),
  Path(r"\\workspace"),
  Path(r"D:\\vegah_slave\\listenai_rtos"),
]
```

When a CU’s `DW_AT_comp_dir` starts with any of these, it’s replaced by a relative path in the report.
(Adjust to your environment—Windows UNC paths are supported.)

---

## CLI

```bash
python3 gen_symbols_report.py <ELF_PATH> [OUTPUT_DIR]
```

* `ELF_PATH`: path to the ELF binary
* `OUTPUT_DIR` (optional): directory to write `symbols.json` (default: current dir)

---

## Example

Tree view in the browser might look like:

```
📁 src (total 3200 bytes)
 ├─ 📁 core (total 2100 bytes)
 │   ├─ 📄 main.c (1500 bytes)
 │   │   ├─ 🔹 main                     900 bytes
 │   │   └─ 🔹 init_system              600 bytes
 │   └─ 📄 utils.c (600 bytes)
 │       └─ 🔹 helper_func              600 bytes
 └─ 📁 drivers (total 1100 bytes)
     ├─ 📄 uart.c (700 bytes)
     └─ 📄 gpio.c (400 bytes)

📁 [NO_DWARF] (total 512 bytes)
 └─ 📁 .text (512 bytes)
     └─ 📄 <elf-symtab> (512 bytes)
         ├─ 🔹 memcpy                   256 bytes
         └─ 🔹 startup_stub             256 bytes
```

---

## Known Limitations

* **Heavily optimized builds** (LTO, inlining) may reduce or distort DWARF mappings.
* **ELF-only symbols** might not map back to a unique source file even with aranges/line tables; those remain under `[NO_DWARF]`.
* Some toolchains emit **absolute `DW_AT_high_pc`** vs **offset**; handled, but malformed entries are skipped.
* Very large binaries with full DWARF can make JSON big and UI heavy; see **Performance Tips**.

---

## Performance Tips

* Prefer **stripped release** with `-g` (DWARF present but without full debug types) to keep DWARF moderate.
* If the JSON becomes large, open `symbols.html` in a modern browser (Chromium/Firefox).
* You can prune tiny symbols in Python (e.g., skip `size < 4`) for a smaller tree.

---

## Troubleshooting

* **No DWARF info**: The generator still emits symbols from ELF tables under `[NO_DWARF]`.
* **Paths look absolute/unwieldy**: Adjust `IGNORE_BASE_PATHS` to your workspace roots.
* **Nothing displays**: Check the console (DevTools) for `symbols.json` load errors (CORS isn’t an issue for local file URLs in most browsers, but some setups may require opening via `http://`).

---

## Project Structure

```
main.py                 # Python generator → symbols.json
web--
    -symbols.html            # Static UI shell
    -symbols.css             # Styles
    -symbols.js              # Rendering & interactions (expand/collapse, exports)
```


If you want optional features (dark mode, per-directory/file thresholds, or re-enabling search limited to **files/symbols** only), you can extend the UI without changing the JSON format.
