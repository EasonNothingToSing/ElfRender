#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Controller layer: pywebview bridge between the HTML UI and the model."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import webview

from .model import DEFAULT_IGNORE_BASE_PATHS, generate_report


class AppController:
    """JS API exposed to the pywebview front-end."""

    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root).resolve()
        self.window: webview.Window | None = None
        self.elf_path: Path | None = None
        self.last_output_dir: Path | None = None

    def set_window(self, window: webview.Window):
        self.window = window

    def _ui_progress(self, pct: int, message: str):
        """Push progress updates to the UI."""

        if not self.window:
            return
        safe_msg = message.replace("\\", "\\\\").replace("\"", "\\\"")
        self.window.evaluate_js(f'window.updateProgress({int(pct)}, "{safe_msg}")')

    def pick_elf(self) -> dict[str, Any]:
        """Open a file dialog and return the selected ELF path."""

        if not self.window:
            return {"ok": False, "error": "Window not ready"}

        paths = self.window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=(
                "All files (*.*)",
                "ELF files (*.elf;*.axf;*.out;*.bin)",
            ),
        )
        if not paths:
            return {"ok": False, "cancelled": True}

        self.elf_path = Path(paths[0]).resolve()
        return {"ok": True, "path": str(self.elf_path)}

    def generate(self, elf_path: str | None, ignore_paths_text: str | None) -> dict[str, Any]:
        """Generate the report into an output directory."""

        try:
            target = Path(elf_path).resolve() if elf_path else (self.elf_path.resolve() if self.elf_path else None)
            if not target:
                return {"ok": False, "error": "No ELF selected"}

            ignore_list = self._parse_ignore_paths(ignore_paths_text)

            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_dir = self.project_root / "out" / f"{target.stem}_{stamp}"

            self._ui_progress(0, "Starting…")
            result = generate_report(
                elf_path=target,
                output_dir=out_dir,
                ignore_base_paths=ignore_list,
                progress_cb=self._ui_progress,
                web_assets_dir=self.project_root / "web",
            )

            self.last_output_dir = result.output_dir
            return {
                "ok": True,
                "output_dir": str(result.output_dir),
                "report_html": str(result.report_html),
                "symbols_json": str(result.symbols_json),
            }
        except Exception as e:
            self._ui_progress(0, "Failed")
            return {"ok": False, "error": str(e)}

    def open_view(self) -> dict[str, Any]:
        """Open the generated report (symbols.html) in a new window."""

        if not self.last_output_dir:
            return {"ok": False, "error": "No report generated yet"}

        report_html = self.last_output_dir / "symbols.html"
        if not report_html.exists():
            return {"ok": False, "error": f"Report not found: {report_html}"}

        # Use file:// URI to avoid internal http server path restrictions (which can lead to 404).
        report_url = report_html.resolve().as_uri()
        webview.create_window("Symbol Report", url=report_url)
        return {"ok": True, "path": str(report_html), "url": report_url}

    @staticmethod
    def _parse_ignore_paths(ignore_paths_text: str | None):
        """Parse ignore paths from a single text input.

        Accepted separators:
        - Newline
        - Semicolon
        """

        if not ignore_paths_text or not ignore_paths_text.strip():
            return list(DEFAULT_IGNORE_BASE_PATHS)

        raw = ignore_paths_text.replace("\r\n", "\n")
        parts = []
        for chunk in raw.split("\n"):
            parts.extend([p.strip() for p in chunk.split(";")])

        paths = [Path(p) for p in parts if p]
        return paths if paths else list(DEFAULT_IGNORE_BASE_PATHS)
