#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ElfRender GUI entrypoint (pywebview)."""

from __future__ import annotations

from pathlib import Path

import webview

from elfrender.controller import AppController


def main():
    project_root = Path(__file__).resolve().parent
    view_dir = project_root / "elfrender" / "view"
    index_html = view_dir / "index.html"
    icon_path = project_root / "icon.ico"

    controller = AppController(project_root=project_root)

    window = webview.create_window(
        "Dwarfer - ELF Symbol Analyzer",
        url=index_html.resolve().as_uri(),
        js_api=controller,
        width=980,
        height=620,
    )
    
    # Set window icon if ico file exists
    if icon_path.exists():
        try:
            import sys
            if sys.platform == 'win32':
                import ctypes
                myappid = 'listenai.dwarfer.analyzer.1.0'
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

    def on_start():
        controller.set_window(window)

    webview.start(on_start, debug=False)


if __name__ == "__main__":
    main()

