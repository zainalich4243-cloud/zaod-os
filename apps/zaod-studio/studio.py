#!/usr/bin/env python3
"""Low-resource host-side IDE for ZAOD application projects."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk


ROOT = Path(__file__).resolve().parents[2]
ZAODC = ROOT / "tools" / "zaodc"
KEYWORDS = re.compile(
    r"\b(?:void|int|char|uint8_t|uint32_t|int64_t|return|if|else|for|while|"
    r"static|const|struct|enum)\b"
)


class CodeEditor(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.gutter = tk.Text(self, width=5, padx=4, takefocus=0, state="disabled")
        self.text = tk.Text(self, wrap="none", undo=True, font=("TkFixedFont", 10))
        scroll = ttk.Scrollbar(self, orient="vertical", command=self._scroll)
        self.text.configure(yscrollcommand=self._scrollbar_changed)
        self.gutter.grid(row=0, column=0, sticky="ns")
        self.text.grid(row=0, column=1, sticky="nsew")
        scroll.grid(row=0, column=2, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.text.tag_configure("keyword", foreground="#805ad5")
        self.text.tag_configure("string", foreground="#22863a")
        self.text.tag_configure("comment", foreground="#6a737d")
        self.text.bind("<<Modified>>", self._changed)
        self._refresh_gutter()

    def _scroll(self, *args: str) -> None:
        self.text.yview(*args)
        self.gutter.yview(*args)

    def _scrollbar_changed(self, first: str, last: str) -> None:
        self.gutter.yview_moveto(first)

    def _changed(self, _event: tk.Event) -> None:
        if self.text.edit_modified():
            self.text.edit_modified(False)
            self._refresh_gutter()
            self._highlight()

    def _refresh_gutter(self) -> None:
        lines = int(self.text.index("end-1c").split(".")[0])
        self.gutter.configure(state="normal")
        self.gutter.delete("1.0", "end")
        self.gutter.insert("1.0", "\n".join(str(line) for line in range(1, lines + 1)))
        self.gutter.configure(state="disabled")

    def _highlight(self) -> None:
        content = self.text.get("1.0", "end-1c")
        for tag in ("keyword", "string", "comment"):
            self.text.tag_remove(tag, "1.0", "end")
        for match in KEYWORDS.finditer(content):
            start = f"1.0 + {match.start()} chars"
            end = f"1.0 + {match.end()} chars"
            self.text.tag_add("keyword", start, end)
        for match in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', content):
            self.text.tag_add(
                "string",
                f"1.0 + {match.start()} chars",
                f"1.0 + {match.end()} chars",
            )
        for match in re.finditer(r"//[^\n]*|/\*[\s\S]*?\*/", content):
            self.text.tag_add(
                "comment",
                f"1.0 + {match.start()} chars",
                f"1.0 + {match.end()} chars",
            )

    def load(self, path: Path) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", path.read_text(encoding="utf-8"))
        self.text.edit_modified(False)
        self._refresh_gutter()
        self._highlight()


class ZaodStudio(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ZAOD Studio")
        self.geometry("960x640")
        self.minsize(720, 480)
        self.project: Path | None = None
        self.source: Path | None = None

        toolbar = ttk.Frame(self, padding=6)
        toolbar.pack(fill="x")
        for label, action in (
            ("New Project", self.new_project),
            ("Open Project", self.open_project),
            ("Open Source", self.open_source),
            ("Save", self.save_source),
            ("Build & Run in Sandbox", self.build_and_run),
            ("Package for Store", self.package_for_store),
        ):
            ttk.Button(toolbar, text=label, command=action).pack(side="left", padx=2)

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.projects = ttk.Treeview(body, show="tree", selectmode="browse", width=24)
        self.projects.bind("<<TreeviewSelect>>", self._select_project)
        body.add(self.projects, weight=1)
        self.editor = CodeEditor(body)
        body.add(self.editor, weight=4)
        self.status = tk.StringVar(
            value="Host-side editor; ZAOD CPL3 execution is not implemented."
        )
        ttk.Label(self, textvariable=self.status, anchor="w", padding=5).pack(fill="x")

    def new_project(self) -> None:
        parent = filedialog.askdirectory(title="Choose a project parent directory")
        if not parent:
            return
        app_id = simpledialog.askstring("New ZAOD Project", "App ID (for example com.example.app):")
        if not app_id:
            return
        destination = Path(parent) / app_id
        result = subprocess.run(
            [str(ZAODC), "new", str(destination), "--app-id", app_id],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            messagebox.showerror("Could not create project", result.stderr.strip())
            return
        self._add_project(destination)
        self._load_project(destination)

    def open_project(self) -> None:
        selected = filedialog.askdirectory(title="Open ZAOD project")
        if selected:
            self._add_project(Path(selected))
            self._load_project(Path(selected))

    def _add_project(self, project: Path) -> None:
        project = project.resolve()
        for item in self.projects.get_children():
            if self.projects.item(item, "values") == (str(project),):
                return
        self.projects.insert("", "end", text=project.name, values=(str(project),))

    def _select_project(self, _event: tk.Event) -> None:
        selected = self.projects.selection()
        if selected:
            self._load_project(Path(self.projects.item(selected[0], "values")[0]))

    def _load_project(self, project: Path) -> None:
        config_path = project / "zaod.json"
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            source = project / "src" / "main.c"
            if not source.is_file():
                source = next((project / "src").glob("*.[cC]"), source)
            self.project = project
            self.source = source
            self.editor.load(source)
            self.status.set(f"{config.get('app_id', project.name)} - {source}")
        except (OSError, json.JSONDecodeError) as error:
            messagebox.showerror("Invalid ZAOD project", str(error))

    def open_source(self) -> None:
        if self.project is None:
            messagebox.showinfo("Open a project first", "Choose or create a ZAOD project.")
            return
        selected = filedialog.askopenfilename(
            initialdir=self.project / "src",
            filetypes=(("C/C++ source", "*.c *.cc *.cpp *.cxx"), ("All files", "*")),
        )
        if selected:
            self.source = Path(selected)
            self.editor.load(self.source)
            self.status.set(str(self.source))

    def save_source(self) -> bool:
        if self.source is None:
            return False
        try:
            self.source.write_text(self.editor.text.get("1.0", "end-1c"), encoding="utf-8")
            self.status.set(f"Saved {self.source}")
            return True
        except OSError as error:
            messagebox.showerror("Could not save source", str(error))
            return False

    def _build(self, output: Path, signing_key: Path | None = None) -> subprocess.CompletedProcess[str]:
        if self.project is None:
            raise RuntimeError("Choose or create a ZAOD project first.")
        command = [str(ZAODC), "build", str(self.project), "--output", str(output)]
        if not self.save_source():
            return subprocess.CompletedProcess(
                command, 1, "", "Could not save the selected source file."
            )
        if signing_key is not None:
            command.extend(["--private-key", str(signing_key)])
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def build_and_run(self) -> None:
        if self.project is None:
            messagebox.showinfo("Open a project first", "Choose or create a ZAOD project.")
            return
        with tempfile.TemporaryDirectory(prefix="zaod-studio-") as directory:
            stage = Path(directory) / "app"
            built = self._build(stage)
            if built.returncode:
                messagebox.showerror("Build failed", built.stderr.strip())
                return
            result = subprocess.run(
                [str(ZAODC), "run", str(stage)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.status.set("Build passed; sandbox execution is unavailable in this kernel.")
        messagebox.showwarning(
            "Sandbox runtime unavailable",
            built.stdout.strip() + "\n\n" + result.stderr.strip(),
        )

    def package_for_store(self) -> None:
        if self.project is None:
            messagebox.showinfo("Open a project first", "Choose or create a ZAOD project.")
            return
        key = filedialog.askopenfilename(
            title="Select the trusted Ed25519 signing key",
            filetypes=(("PEM files", "*.pem"), ("All files", "*")),
        )
        if not key:
            return
        output = filedialog.asksaveasfilename(
            title="Export signed .zaod package",
            defaultextension=".zaod",
            filetypes=(("ZAOD packages", "*.zaod"),),
        )
        if not output:
            return
        result = self._build(Path(output), Path(key))
        if result.returncode:
            messagebox.showerror("Package failed", result.stderr.strip())
            return
        self.status.set(f"Created {output}")
        messagebox.showinfo("Package ready", result.stdout.strip())


if __name__ == "__main__":
    ZaodStudio().mainloop()
