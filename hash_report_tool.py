"""
eDiscovery Hash Report Tool  (v1.0)
===================================

A small, fully offline GUI tool for litigation support staff. The user picks a
folder, chooses one or more hash algorithms (MD5 / SHA-1 / SHA-256), and clicks
Run. The tool walks every subfolder, hashes every file, and writes a CSV report
named "Hash_Report_YYYYMMDD_HHMMSS.csv" next to (in the parent of) the selected
folder.

Design notes
------------
* Standard library only (tkinter, hashlib, csv, os, ...). No network modules
  are imported and no network calls are made anywhere in this file.
* The report is written to the PARENT of the selected folder so the tool never
  adds files to the evidence set it is hashing. (If the selected folder is a
  drive root such as E:\\, or the parent can't be written to, the user is asked
  where to save.)
* Files are read in 1 MB chunks and every selected algorithm is updated from
  the same chunk, so each file is read from disk only once, and memory use
  stays flat no matter how large the file is.
* Unreadable files (locked, permission denied, vanished mid-run, ...) are
  skipped and listed in an "ERRORS" section at the bottom of the CSV.
* Hashing runs on a background thread so the window stays responsive.

Build (see BUILD_INSTRUCTIONS.txt):
    pyinstaller --onefile --windowed --name HashReportTool hash_report_tool.py
"""

import csv
import datetime
import getpass
import hashlib
import os
import platform
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_NAME = "eDiscovery Hash Report Tool"
TOOL_VERSION = "v1.0"

# Read files 1 MB at a time: large enough to be fast, small enough that even
# multi-hundred-GB files never need much memory.
CHUNK_SIZE = 1024 * 1024

# Display name -> hashlib name. Order here is the column order in the report.
ALGORITHMS = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
}

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Helper functions (no GUI code here, so they can be tested on their own)
# ---------------------------------------------------------------------------

def timestamp_now():
    """Current local date/time, with UTC offset, e.g. 2026-09-23 14:05:11 -0400."""
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def format_mtime(epoch_seconds):
    """Turn a file's modified time (seconds since epoch) into local date/time text."""
    return (
        datetime.datetime.fromtimestamp(epoch_seconds)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S %z")
    )


def to_long_path(path):
    """
    On Windows, return the "extended-length" form of a path (\\\\?\\C:\\...) so
    that files nested deeper than the old 260-character limit can still be
    opened. On other systems the path is returned unchanged.
    """
    path = os.path.abspath(path)
    if not IS_WINDOWS or path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):  # network share: \\server\share\...
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def from_long_path(path):
    """Undo to_long_path() so paths shown to the user look normal."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def collect_files(root, errors):
    """
    Walk `root` and all subfolders. Returns a sorted list of
    (full_path, size_in_bytes) tuples. Folders or files that can't be read
    are appended to `errors` as (display_path, message) and skipped.
    """
    files = []
    long_root = to_long_path(root)

    def on_walk_error(err):
        # Called by os.walk when a folder can't be listed (e.g. access denied).
        folder = from_long_path(getattr(err, "filename", "") or "")
        errors.append((folder, "Folder could not be opened: "
                       + str(getattr(err, "strerror", None) or err)))

    # followlinks=False (default): don't follow shortcuts/junctions into other
    # locations, which could loop forever or pull in files outside the folder.
    for dirpath, dirnames, filenames in os.walk(long_root, onerror=on_walk_error):
        dirnames.sort()  # walk subfolders in a predictable order
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                size = os.stat(full).st_size
            except OSError as exc:
                errors.append((from_long_path(full), describe_error(exc)))
                continue
            files.append((full, size))

    files.sort(key=lambda item: item[0].lower())
    return files


def describe_error(exc):
    """Short, plain-English description of a file error for the report."""
    if isinstance(exc, PermissionError):
        return "Access denied or file is locked/in use (" + str(exc.strerror) + ")"
    if isinstance(exc, FileNotFoundError):
        return "File was moved or deleted during processing"
    return exc.__class__.__name__ + ": " + str(getattr(exc, "strerror", None) or exc)


def hash_file(path, algo_names, on_bytes=None):
    """
    Hash one file with every algorithm in `algo_names` (display names such as
    "MD5"), reading it only once, CHUNK_SIZE bytes at a time.

    `on_bytes(n)` is called after each chunk with the number of bytes just read
    (used to drive the progress bar). Returns {display_name: hex_digest}.
    Raises OSError if the file can't be read.
    """
    hashers = {name: hashlib.new(ALGORITHMS[name]) for name in algo_names}
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
            if on_bytes:
                on_bytes(len(chunk))
    return {name: h.hexdigest() for name, h in hashers.items()}


def default_report_path(root):
    """
    Report goes in the PARENT of the selected folder, so it never lands inside
    the folder being hashed. Returns None when the folder has no parent (e.g.
    a drive root like E:\\), in which case the GUI asks the user where to save.
    """
    root = os.path.abspath(root)
    parent = os.path.dirname(root)
    if not parent or os.path.normcase(parent) == os.path.normcase(root):
        return None
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(parent, "Hash_Report_" + stamp + ".csv")
    # Extremely unlikely, but never overwrite an existing report.
    counter = 2
    while os.path.exists(path):
        path = os.path.join(parent, "Hash_Report_%s_%d.csv" % (stamp, counter))
        counter += 1
    return path


def run_hash_job(root, algo_names, report_path, progress=None):
    """
    The complete job: scan, hash, and write the CSV report.

    `progress(event, **info)` is an optional callback used by the GUI:
        progress("scanning")
        progress("start", total_files=..., total_bytes=...)
        progress("file", index=..., total_files=..., name=...)
        progress("bytes", done_bytes=...)

    Returns (files_hashed, errors) where errors is a list of (path, message).
    """
    progress = progress or (lambda *a, **k: None)
    algo_names = [a for a in ALGORITHMS if a in algo_names]  # keep column order
    errors = []
    started = timestamp_now()

    progress("scanning")
    files = collect_files(root, errors)
    total_bytes = sum(size for _, size in files)
    progress("start", total_files=len(files), total_bytes=total_bytes)

    long_root = to_long_path(root)
    header = (["File Name", "Full File Path", "File Size (bytes)", "Date Modified"]
              + algo_names
              + ["Date/Time Hash Generated", "Tool Version"])

    hashed = 0
    done_bytes = [0]

    def add_bytes(n):
        done_bytes[0] += n
        progress("bytes", done_bytes=done_bytes[0])

    # utf-8-sig adds a byte-order mark so Excel shows non-English file names
    # correctly. newline="" is required by the csv module.
    with open(report_path, "w", newline="", encoding="utf-8-sig") as out:
        writer = csv.writer(out)
        writer.writerow(header)

        for index, (full, size) in enumerate(files, start=1):
            rel = os.path.relpath(full, long_root)
            progress("file", index=index, total_files=len(files),
                     name=os.path.basename(full))
            bytes_before = done_bytes[0]
            try:
                # Record size/modified date immediately before hashing.
                st = os.stat(full)
                digests = hash_file(full, algo_names, add_bytes)
            except OSError as exc:
                errors.append((from_long_path(full), describe_error(exc)))
                # Count the skipped file as "done" so the progress bar still
                # reaches 100%.
                done_bytes[0] = bytes_before + size
                progress("bytes", done_bytes=done_bytes[0])
                continue

            writer.writerow(
                [os.path.basename(full), rel, st.st_size, format_mtime(st.st_mtime)]
                + [digests[a] for a in algo_names]
                + [timestamp_now(), TOOL_VERSION]
            )
            hashed += 1

        # --- ERRORS section -------------------------------------------------
        # A CSV has no "tabs", so errors go in their own clearly labelled
        # section below the main table. The main table stays intact above it.
        writer.writerow([])
        writer.writerow(["ERRORS - files/folders that could NOT be hashed"])
        writer.writerow(["File Name", "Full Path", "Error"])
        if errors:
            for path, message in errors:
                writer.writerow([os.path.basename(path.rstrip("\\/")), path, message])
        else:
            writer.writerow(["(none)"])

        # --- SUMMARY section ------------------------------------------------
        # Basic chain-of-custody context. All values come from the local
        # machine; nothing is looked up over a network.
        writer.writerow([])
        writer.writerow(["SUMMARY"])
        for label, value in [
            ("Source Folder", os.path.abspath(root)),
            ("Files Found", len(files)),
            ("Files Hashed", hashed),
            ("Errors", len(errors)),
            ("Algorithms", ", ".join(algo_names)),
            ("Job Started", started),
            ("Job Finished", timestamp_now()),
            ("Run By (Windows user)", safe_username()),
            ("Computer Name", platform.node()),
            ("Tool", TOOL_NAME + " " + TOOL_VERSION),
        ]:
            writer.writerow([label, value])

    return hashed, errors


def safe_username():
    try:
        return getpass.getuser()
    except Exception:
        return "(unknown)"


def open_in_file_browser(report_path):
    """Open the folder containing the report, with the report highlighted."""
    try:
        if IS_WINDOWS:
            # explorer.exe /select highlights the file inside its folder.
            subprocess.Popen(["explorer", "/select,", os.path.normpath(report_path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", report_path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(report_path)])
    except Exception as exc:
        messagebox.showerror(TOOL_NAME, "Could not open the folder:\n%s" % exc)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class HashReportApp:
    """The main window. Deliberately minimal for non-technical users."""

    def __init__(self, root, initial_folder=None):
        self.root = root
        self.folder = None
        self.running = False
        self.events = queue.Queue()  # messages from the worker thread
        self.total_bytes = 0
        self.total_files = 0

        root.title(TOOL_NAME + " " + TOOL_VERSION)
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        pad = {"padx": 12, "pady": 6}
        frame = ttk.Frame(root, padding=10)
        frame.grid(sticky="nsew")

        # Step 1: folder
        ttk.Label(frame, text="1. Choose the folder to hash:",
                  font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", **pad)
        folder_row = ttk.Frame(frame)
        folder_row.grid(row=1, column=0, sticky="we", padx=12)
        ttk.Button(folder_row, text="Select Folder...",
                   command=self.select_folder).pack(side="left")
        self.folder_label = ttk.Label(folder_row, text="(no folder selected)",
                                      width=55, foreground="gray")
        self.folder_label.pack(side="left", padx=10)

        # Step 2: algorithms (checkboxes so more than one can be chosen)
        ttk.Label(frame, text="2. Choose hash type(s):",
                  font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", **pad)
        algo_row = ttk.Frame(frame)
        algo_row.grid(row=3, column=0, sticky="w", padx=12)
        self.algo_vars = {}
        for name in ALGORITHMS:
            var = tk.BooleanVar(value=(name == "MD5"))  # MD5 on by default
            ttk.Checkbutton(algo_row, text=name, variable=var).pack(side="left", padx=(0, 20))
            self.algo_vars[name] = var

        # Step 3: run
        ttk.Label(frame, text="3. Click Run:",
                  font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="w", **pad)
        self.run_button = ttk.Button(frame, text="Run", command=self.start)
        self.run_button.grid(row=5, column=0, sticky="w", padx=12)

        # Progress
        self.progress = ttk.Progressbar(frame, length=520, mode="determinate", maximum=1000)
        self.progress.grid(row=6, column=0, sticky="we", padx=12, pady=(14, 4))
        self.status = ttk.Label(frame, text="Ready.", width=75)
        self.status.grid(row=7, column=0, sticky="w", padx=12)

        # Footer
        ttk.Separator(frame).grid(row=8, column=0, sticky="we", pady=(14, 4))
        ttk.Label(frame, text="For internal eDiscovery use only.",
                  foreground="gray").grid(row=9, column=0)

        # Allows dragging a folder onto the .exe icon (Windows passes it as
        # the first command-line argument).
        if initial_folder and os.path.isdir(initial_folder):
            self.set_folder(initial_folder)

    # -- folder selection ---------------------------------------------------

    def select_folder(self):
        chosen = filedialog.askdirectory(title="Select the folder to hash")
        if chosen:
            self.set_folder(chosen)

    def set_folder(self, path):
        self.folder = os.path.abspath(path)
        self.folder_label.config(text=self.folder, foreground="black")
        self.status.config(text="Ready.")
        self.progress["value"] = 0

    # -- run ----------------------------------------------------------------

    def start(self):
        if self.running:
            return
        if not self.folder or not os.path.isdir(self.folder):
            messagebox.showwarning(TOOL_NAME, "Please select a folder first.")
            return
        algos = [name for name, var in self.algo_vars.items() if var.get()]
        if not algos:
            messagebox.showwarning(TOOL_NAME, "Please tick at least one hash type.")
            return

        report_path = self.choose_report_path()
        if not report_path:
            return

        self.running = True
        self.run_button.config(state="disabled")
        self.progress["value"] = 0
        worker = threading.Thread(target=self.worker,
                                  args=(self.folder, algos, report_path), daemon=True)
        worker.start()
        self.root.after(100, self.poll_events)

    def choose_report_path(self):
        """
        Work out where the report will go and make sure we can write there
        BEFORE spending time hashing. Falls back to a Save As dialog.
        """
        path = default_report_path(self.folder)
        if path and self.can_write(path):
            return path

        messagebox.showinfo(
            TOOL_NAME,
            "The report can't be saved next to the selected folder.\n\n"
            "Please choose where to save the report. (Tip: don't save it "
            "inside the folder being hashed.)")
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Save hash report as",
            initialfile="Hash_Report_" + stamp + ".csv",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")])
        if path and self.can_write(path):
            return path
        if path:
            messagebox.showerror(TOOL_NAME, "Can't write to:\n" + path)
        return None

    @staticmethod
    def can_write(path):
        """Create (then remove) the report file to confirm the location is writable."""
        try:
            existed = os.path.exists(path)
            with open(path, "a"):
                pass
            if not existed:
                os.remove(path)
            return True
        except OSError:
            return False

    def worker(self, folder, algos, report_path):
        """Runs on a background thread. Talks to the GUI only via self.events."""
        try:
            hashed, errors = run_hash_job(
                folder, algos, report_path,
                progress=lambda event, **info: self.events.put((event, info)))
            self.events.put(("done", {"hashed": hashed, "errors": errors,
                                      "report_path": report_path}))
        except Exception as exc:  # anything unexpected: report, don't crash
            self.events.put(("failed", {"error": exc}))

    def poll_events(self):
        """Apply worker updates to the GUI (tkinter must only be touched here)."""
        latest_bytes = None
        try:
            while True:
                event, info = self.events.get_nowait()
                if event == "scanning":
                    self.progress.config(mode="indeterminate")
                    self.progress.start(15)
                    self.status.config(text="Scanning folders...")
                elif event == "start":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=0)
                    self.total_bytes = info["total_bytes"]
                    self.total_files = info["total_files"]
                    self.status.config(text="Found %d files." % info["total_files"])
                elif event == "file":
                    name = info["name"]
                    if len(name) > 45:
                        name = name[:42] + "..."
                    self.status.config(text="Processing file %d of %d:  %s" % (
                        info["index"], info["total_files"], name))
                    if not self.total_bytes and info["total_files"]:
                        # All files are empty: drive the bar by file count.
                        self.progress["value"] = 1000 * info["index"] / info["total_files"]
                elif event == "bytes":
                    latest_bytes = info["done_bytes"]
                elif event == "done":
                    self.finish(info)
                    return
                elif event == "failed":
                    self.finish_failed(info["error"])
                    return
        except queue.Empty:
            pass
        if latest_bytes is not None and self.total_bytes:
            self.progress["value"] = 1000 * latest_bytes / self.total_bytes
        self.root.after(100, self.poll_events)

    def finish(self, info):
        self.running = False
        self.run_button.config(state="normal")
        self.progress.stop()
        self.progress.config(mode="determinate", value=1000)
        hashed, errors, report_path = info["hashed"], info["errors"], info["report_path"]
        self.status.config(text="Complete. %d files hashed." % hashed)

        message = "Complete. %d files hashed. Report saved to:\n%s" % (hashed, report_path)
        if errors:
            message += ("\n\n%d file(s)/folder(s) could not be read. They are listed "
                        "in the ERRORS section at the bottom of the report." % len(errors))
        self.show_complete_dialog(message, report_path)

    def finish_failed(self, error):
        self.running = False
        self.run_button.config(state="normal")
        self.progress.stop()
        self.progress.config(mode="determinate", value=0)
        self.status.config(text="Stopped because of an error.")
        messagebox.showerror(TOOL_NAME, "The job could not be completed:\n\n%s" % error)

    def show_complete_dialog(self, message, report_path):
        """Popup with the result plus an 'Open Folder' button."""
        win = tk.Toplevel(self.root)
        win.title(TOOL_NAME)
        win.resizable(False, False)
        win.transient(self.root)
        ttk.Label(win, text=message, wraplength=460, justify="left",
                  padding=16).pack()
        buttons = ttk.Frame(win, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")

        def open_folder():
            open_in_file_browser(report_path)
            win.destroy()

        ttk.Button(buttons, text="Open Folder", command=open_folder).pack(side="right")
        ttk.Button(buttons, text="OK", command=win.destroy).pack(side="right", padx=8)
        win.grab_set()
        win.focus_set()

    def on_close(self):
        if self.running and not messagebox.askyesno(
                TOOL_NAME, "Hashing is still running. The report will be "
                           "INCOMPLETE if you close now.\n\nClose anyway?"):
            return
        self.root.destroy()


def main():
    # Sharper text on high-resolution Windows screens (harmless if unavailable).
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    initial = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    HashReportApp(root, initial_folder=initial)
    root.mainloop()


if __name__ == "__main__":
    main()
