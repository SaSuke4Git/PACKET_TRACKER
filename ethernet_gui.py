#!/usr/bin/env python3
"""Tkinter GUI for the Ethernet Frame Analysis System (uses ethernet_monitor.py as its core).

Run:  python ethernet_gui.py      (live mode needs:  pip install scapy  + Npcap on Windows)
"""
import csv, queue, threading, time, tkinter as tk
from collections import Counter
from dataclasses import asdict
from tkinter import filedialog, messagebox, ttk

import ethernet_monitor as core

COLS = [("no", "#", 40), ("time", "Time", 70), ("dst", "Destination", 130), ("src", "Source", 130),
        ("ethertype", "Type", 90), ("vlan", "VLAN", 45), ("frame_len", "Len", 50),
        ("payload_len", "Payload", 60), ("fcs_rx", "FCS rx", 75), ("fcs_calc", "FCS calc", 75),
        ("status", "Status", 80), ("detail", "Detail", 320)]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ethernet Frame Analysis System")
        self.geometry("1280x740")
        self.q = queue.Queue()
        self.stop_evt = threading.Event()
        self.worker = None
        self.frames, self.records, self.raws = [], [], {}
        self.counter = 0
        self._build()
        self.after(100, self._poll)

    # ------------------------------------------------------------ layout
    def _build(self):
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        self.mode = tk.StringVar(value="Simulation")
        self.err = tk.DoubleVar(value=0.15)
        self.iface = tk.StringVar()
        self.fmac = tk.StringVar()
        self.ftype = tk.StringVar(value="All")

        ttk.Label(top, text="Mode").grid(row=0, column=0)
        ttk.Combobox(top, textvariable=self.mode, width=20, state="readonly",
                     values=["Simulation", "Live capture (Scapy)"]).grid(row=0, column=1, padx=4)
        ttk.Label(top, text="Error rate").grid(row=0, column=2)
        ttk.Spinbox(top, from_=0, to=1, increment=0.05, width=5,
                    textvariable=self.err).grid(row=0, column=3, padx=4)
        ttk.Label(top, text="Interface").grid(row=0, column=4)
        ttk.Entry(top, textvariable=self.iface, width=18).grid(row=0, column=5, padx=4)
        ttk.Label(top, text="MAC filter").grid(row=1, column=0, pady=4)
        ttk.Entry(top, textvariable=self.fmac, width=22).grid(row=1, column=1, padx=4)
        ttk.Label(top, text="Type").grid(row=1, column=2)
        ttk.Combobox(top, textvariable=self.ftype, width=8, state="readonly",
                     values=["All", "IPv4", "ARP", "IPv6", "LLDP"]).grid(row=1, column=3)

        btns = ttk.Frame(top)
        btns.grid(row=0, column=6, rowspan=2, padx=12)
        for i, (t, c) in enumerate([("Start", self.start), ("Stop", self.stop), ("Clear", self.clear),
                                    ("Export CSV", self.export_csv), ("Export PCAP", self.export_pcap)]):
            ttk.Button(btns, text=t, command=c).grid(row=i // 3, column=i % 3, padx=2, pady=2)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=6)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLS], show="headings", height=16)
        for key, title, w in COLS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=w, anchor="w")
        self.tree.tag_configure("err", background="#f8d0d0")
        self.tree.tag_configure("warn", background="#fbe6b8")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_hex)

        bottom = ttk.Frame(self, padding=6)
        bottom.pack(fill="x")
        self.hex = tk.Text(bottom, height=8, width=84, font=("Courier", 9), state="disabled")
        self.hex.pack(side="left")
        right = ttk.Frame(bottom)
        right.pack(side="left", fill="both", expand=True, padx=8)
        self.stat = tk.StringVar(value="Frames: 0")
        ttk.Label(right, textvariable=self.stat, font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
        self.canvas = tk.Canvas(right, height=130, bg="white", highlightthickness=1,
                                highlightbackground="#bbb")
        self.canvas.pack(fill="both", expand=True)

    # ------------------------------------------------------------ capture control
    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_evt.clear()
        mode, rate, iface = self.mode.get(), self.err.get(), self.iface.get().strip() or None
        if mode == "Simulation":
            core.init_mac_pool(6)
        self.worker = threading.Thread(target=self._run, args=(mode, rate, iface), daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_evt.set()

    def _run(self, mode, rate, iface):
        try:
            if mode == "Simulation":
                src = core.sim_source(0, rate, 0.15, self.stop_evt.is_set)
            else:
                src = core.scapy_source(iface, 0, self.stop_evt.is_set)
            for item in src:
                if self.stop_evt.is_set():
                    break
                self.q.put(item)
        except Exception as e:                      # shown in the UI thread
            self.q.put(e)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.frames.clear(); self.records.clear(); self.raws.clear()
        self.counter = 0
        self._stats()

    # ------------------------------------------------------------ UI updates
    def _poll(self):
        changed = False
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, Exception):
                    self.stop_evt.set()
                    messagebox.showerror("Capture error", str(item))
                else:
                    changed |= self._add(*item)
        except queue.Empty:
            pass
        if changed:
            self._stats()
        self.after(100, self._poll)

    def _add(self, raw, has_fcs):
        self.counter += 1
        f = core.parse_frame(raw, self.counter, has_fcs)
        etype = "" if self.ftype.get() == "All" else self.ftype.get()
        if not core.passes_filter(f, self.fmac.get().strip(), etype):
            return False
        tag = {"CRC ERROR": "err", "RUNT": "err", "WARN": "warn"}.get(f.status, "")
        iid = self.tree.insert("", "end", values=[getattr(f, k) for k, _, _ in COLS], tags=(tag,))
        self.raws[iid] = raw
        self.frames.append(f)
        self.records.append((time.time(), raw))
        self.tree.see(iid)
        return True

    def _show_hex(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        raw, lines = self.raws[sel[0]], []
        for i in range(0, len(raw), 16):
            ch = raw[i:i + 16]
            hx = " ".join(f"{b:02x}" for b in ch)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in ch)
            lines.append(f"{i:04x}  {hx:<47}  {asc}")
        self.hex.config(state="normal")
        self.hex.delete("1.0", "end")
        self.hex.insert("end", "\n".join(lines))
        self.hex.config(state="disabled")

    def _stats(self):
        n = len(self.frames)
        cv = self.canvas
        cv.delete("all")
        if not n:
            self.stat.set("Frames: 0")
            return
        bad = sum(f.status == "CRC ERROR" for f in self.frames)
        total = sum(f.frame_len for f in self.frames)
        self.stat.set(f"Frames: {n}   Bytes: {total}   CRC errors: {bad} ({100 * bad / n:.1f}%)")
        counts = Counter(f.ethertype for f in self.frames)
        counts["CRC ERROR"] = bad
        mx, h = max(counts.values()), 130
        bw = max(40, min(90, (cv.winfo_width() or 600) // (len(counts) + 1)))
        for i, (k, v) in enumerate(counts.most_common()):
            x, bh = 15 + i * (bw + 10), int((h - 45) * v / mx)
            cv.create_rectangle(x, h - 20 - bh, x + bw, h - 20, outline="",
                                fill="#d9534f" if k == "CRC ERROR" else "#4a90d9")
            cv.create_text(x + bw / 2, h - 9, text=k, font=("TkDefaultFont", 8))
            cv.create_text(x + bw / 2, h - 28 - bh, text=str(v), font=("TkDefaultFont", 8))

    # ------------------------------------------------------------ export
    def export_csv(self):
        if not self.frames:
            return messagebox.showinfo("Export", "No frames captured yet.")
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(asdict(self.frames[0]).keys()))
                w.writeheader()
                w.writerows(asdict(f) for f in self.frames)

    def export_pcap(self):
        if not self.records:
            return messagebox.showinfo("Export", "No frames captured yet.")
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if path:
            core.write_pcap(path, self.records)


def launch():
    App().mainloop()


if __name__ == "__main__":
    launch()