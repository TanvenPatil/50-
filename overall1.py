# dashboard_with_backend.py (modified: medium/high beep + email)
import os
import time
import threading
import queue
import hashlib
import math
import random
from collections import deque

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from ttkbootstrap import Style
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Optional sound on Windows
try:
    import winsound
except Exception:
    winsound = None
import ctypes
ctypes.windll.user32.MessageBoxW(0, "Test Popup Alert", "HONEYPOT ALERT", 0x10)


# Email imports
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# -----------------------
# Config - EDIT BEFORE RUN
# -----------------------
HONEYPOT_PATH = r"C:\Users\tanve.PREDATOR\OneDrive\Desktop\Ransomware\honeypot"  # <<-- Set this to your honeypot folder
POLL_INTERVAL = 1000  # ms for UI polling
MONITOR_POLL_SECONDS = 2  # seconds between folder scans in monitor thread

# Email placeholders (not enabled by default)
EMAIL_ENABLED = True
SMTP_CONFIG = {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "tanvenpatil1510@gmail.com",
    "pass": "lkql peht joei rtsk",
    "to": "tanvenpatil1510@gmail.com"
}

# Detection thresholds
ENTROPY_SUSPECT = 7.5
ACCESS_WINDOW = 10
ACCESS_THRESHOLD = 5

# Simple XOR key for demo encryption (reversible)
XOR_KEY = 0x7F

# Event queue for monitor -> UI
event_queue = queue.Queue()

# -----------------------
# Helper utilities
# -----------------------
def md5_of_bytes(bts):
    return hashlib.md5(bts).hexdigest()

def sample_bytes(path, size=1024):
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except Exception:
        return b""

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0]*256
    for b in data:
        counts[b] += 1
    ent = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def get_file_info(path):
    try:
        st = os.stat(path)
        sample = sample_bytes(path, 1024)
        return {
            "hash": md5_of_bytes(sample),
            "access_time": st.st_atime,
            "entropy": calc_entropy(sample),
            "size": st.st_size
        }
    except Exception:
        return None

def load_file_states(root):
    state = {}
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            info = get_file_info(p)
            if info is not None:
                state[p] = info
    return state

# -----------------------
# Fake ransomware (demo) - operates only inside HONEYPOT_PATH
# -----------------------
def xor_transform(data: bytes) -> bytes:
    return bytes([b ^ XOR_KEY for b in data])

def attack_low(root=HONEYPOT_PATH):
    count = 0
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            if p.endswith(".fake"):
                continue
            try:
                new = p + ".fake"
                os.rename(p, new)
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":"LOW",
                                 "msg": f"[FAKE-ATTACK low] Renamed {os.path.basename(p)} -> .fake",
                                 "asset": os.path.basename(new)})
                count += 1
            except Exception as e:
                print("rename error:", e)
    return count

def attack_medium(root=HONEYPOT_PATH):
    count = 0
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            try:
                with open(p, "rb+") as f:
                    data = f.read()
                    if not data:
                        continue
                    half = len(data)//2
                    new = xor_transform(data[:half]) + data[half:]
                    f.seek(0); f.write(new); f.truncate()
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":"MEDIUM",
                                 "msg": f"[FAKE-ATTACK med] Partially encrypted {os.path.basename(p)}",
                                 "asset": os.path.basename(p)})
                count += 1
            except Exception as e:
                print("partial encrypt error:", e)
    return count

def attack_high(root=HONEYPOT_PATH):
    count = 0
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            try:
                with open(p, "rb+") as f:
                    data = f.read()
                    if not data:
                        continue
                    new = xor_transform(data)
                    f.seek(0); f.write(new); f.truncate()
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":"HIGH",
                                 "msg": f"[FAKE-ATTACK high] Entire file encrypted {os.path.basename(p)}",
                                 "asset": os.path.basename(p)})
                count += 1
            except Exception as e:
                print("encrypt error:", e)
    return count

def restore_files(root=HONEYPOT_PATH):
    count = 0
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            if p.endswith(".fake"):
                try:
                    new = p[:-5]
                    os.rename(p, new)
                    event_queue.put({"time": time.time(), "type":"INFO", "severity":"LOW",
                                     "msg": f"[RESTORE] Renamed back {os.path.basename(new)}",
                                     "asset": os.path.basename(new)})
                except Exception as e:
                    print("rename back error:", e)
    for r, _, files in os.walk(root):
        for name in files:
            p = os.path.join(r, name)
            try:
                with open(p, "rb+") as f:
                    data = f.read()
                    if not data: continue
                    new = xor_transform(data)
                    f.seek(0); f.write(new); f.truncate()
                event_queue.put({"time": time.time(), "type":"INFO", "severity":"LOW",
                                 "msg": f"[RESTORE] Attempted decrypt {os.path.basename(p)}",
                                 "asset": os.path.basename(p)})
                count += 1
            except Exception as e:
                print("restore error:", e)
    return count

# -----------------------
# Alert utilities (beeps + email)
# -----------------------
def play_beep(seconds=5, freq=1000, dur=300):
    """Play beep for given seconds. On Windows uses winsound, otherwise prints bell."""
    if winsound:
        end = time.time() + seconds
        while time.time() < end:
            winsound.Beep(freq, dur)
            time.sleep(0.05)
    else:
        end = time.time() + seconds
        while time.time() < end:
            print("\a", end="", flush=True)
            time.sleep(0.4)

def send_email(subject, body):
    """Send email using SMTP_CONFIG if EMAIL_ENABLED=True. Non-blocking send in a thread."""
    if not EMAIL_ENABLED:
        return
    cfg = SMTP_CONFIG
    required = ("host","port","user","pass","to")
    if not all(k in cfg for k in required):
        print("[EMAIL] SMTP_CONFIG incomplete; skipping email")
        return

    def _send():
        try:
            msg = MIMEMultipart()
            msg["From"] = cfg["user"]
            msg["To"] = cfg["to"]
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
                server.starttls()
                server.login(cfg["user"], cfg["pass"])
                server.send_message(msg)
            print("[EMAIL] Sent:", subject)
        except Exception as e:
            print("[EMAIL] Failed:", e)

    threading.Thread(target=_send, daemon=True).start()

def notify_high_risk(msg, asset=None):
    """Notify high-risk: queue event, start long beep, send email."""
    event_queue.put({"time": time.time(), "type":"ALERT", "severity":"HIGH",
                     "msg": f"[ALERT] {msg}", "asset": asset})
    threading.Thread(target=play_beep, args=(5,1000,300), daemon=True).start()
    # send email (non-blocking)
    send_email("Honeypot ALERT - HIGH", f"{msg}\nAsset: {asset}\nPath: {HONEYPOT_PATH}")

def notify_medium_risk(msg, asset=None):
    """Notify medium-risk: queue event, short beep, send email."""
    event_queue.put({"time": time.time(), "type":"ALERT", "severity":"MEDIUM",
                     "msg": f"[ALERT] {msg}", "asset": asset})
    threading.Thread(target=play_beep, args=(2,800,250), daemon=True).start()
    send_email("Honeypot ALERT - MEDIUM", f"{msg}\nAsset: {asset}\nPath: {HONEYPOT_PATH}")

# -----------------------
# Monitor loop (polling)
# -----------------------
def monitor_loop(event_queue, stop_event, honeypot_root, interval=MONITOR_POLL_SECONDS):
    """Scans honeypot folder and pushes events to event_queue."""
    if not os.path.isdir(honeypot_root):
        event_queue.put({"time": time.time(), "type":"INFO", "severity":"LOW",
                         "msg": f"Honeypot folder missing: {honeypot_root}", "asset": None})
        return
    recent_accesses = deque()
    prev = load_file_states(honeypot_root)
    while not stop_event.is_set():
        time.sleep(interval)
        curr = load_file_states(honeypot_root)

        # check deleted/modified/access bursts
        for path, old in list(prev.items()):
            if path not in curr:
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":"MEDIUM",
                                 "msg": f"File deleted: {os.path.basename(path)}", "asset": os.path.basename(path)})
                # send email for deletion (medium)
                notify_medium_risk(f"File deleted: {os.path.basename(path)}", os.path.basename(path))
                continue

            new = curr[path]
            # modified (hash changed)
            if new["hash"] != old["hash"]:
                sev = "LOW"
                msg = f"File modified: {os.path.basename(path)}"
                # if sample entropy very high -> possible encryption
                if new["entropy"] > ENTROPY_SUSPECT:
                    sev = "HIGH"
                    msg = f"High entropy modification (likely encryption): {os.path.basename(path)}"
                # push event
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":sev, "msg":msg, "asset":os.path.basename(path)})
                if sev == "HIGH":
                    notify_high_risk(msg, os.path.basename(path))
                elif sev == "LOW":
                    # for LOW we just queue event (no email or long beep)
                    pass

            # access frequency
            if new["access_time"] != old["access_time"]:
                recent_accesses.append(time.time())
                while recent_accesses and time.time() - recent_accesses[0] > ACCESS_WINDOW:
                    recent_accesses.popleft()
                if len(recent_accesses) >= ACCESS_THRESHOLD:
                    msg = f"Burst of file accesses (>= {ACCESS_THRESHOLD} in {ACCESS_WINDOW}s)"
                    event_queue.put({"time": time.time(), "type":"ALERT", "severity":"MEDIUM", "msg":msg, "asset": os.path.basename(path)})
                    # notify medium risk (short beep + email)
                    notify_medium_risk(msg, os.path.basename(path))
                    recent_accesses.clear()

        # new files & suspicious extensions
        for path in curr:
            if path not in prev:
                lower = path.lower()
                sev = "MEDIUM" if lower.endswith(('.locked', '.crypt', '.enc', '.encrypted', '.fake')) else "LOW"
                msg = f"New file detected: {os.path.basename(path)}"
                event_queue.put({"time": time.time(), "type":"ALERT", "severity":sev, "msg":msg, "asset":os.path.basename(path)})
                if sev == "MEDIUM":
                    notify_medium_risk(msg, os.path.basename(path))

        prev = curr

# -----------------------
# UI - Dashboard (your base UI extended)
# -----------------------
class HoneypotDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ransomware Honeypot Dashboard")
        self.geometry("1200x700")
        Style(theme="darkly")  # requires ttkbootstrap

        # Header
        header = ttk.Frame(self, padding=10); header.pack(fill="x")
        ttk.Label(header, text="Ransomware Honeypot Dashboard", font=("Helvetica", 18, "bold")).pack(side="left")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(header, textvariable=self.status_var, bootstyle="success-inverse").pack(side="right", padx=8)

        ttk.Button(header, text="Start Monitor", bootstyle="success-outline", command=self.start_monitor).pack(side="right", padx=5)
        ttk.Button(header, text="Stop Monitor", bootstyle="danger-outline", command=self.stop_monitor).pack(side="right", padx=5)
        ttk.Button(header, text="Simulate Attack", bootstyle="warning-outline", command=self.ui_simulate_attack).pack(side="right", padx=5)
        ttk.Button(header, text="Restore Files", bootstyle="info-outline", command=self.ui_restore_files).pack(side="right", padx=5)

        # Main layout
        body = ttk.Frame(self); body.pack(fill="both", expand=True)

        # Left sidebar
        sidebar = ttk.Frame(body, padding=10); sidebar.pack(side="left", fill="y")
        ttk.Label(sidebar, text="Services Status", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0,5))
        self.services = {}
        for svc in ["Monitor Service", "Windows Audit", "Email Notifier", "Auto-Kill"]:
            var = tk.StringVar(value="Stopped")
            frame = ttk.Frame(sidebar); frame.pack(fill="x", pady=6)
            ttk.Label(frame, text=svc).pack(side="left")
            lbl = ttk.Label(frame, textvariable=var)
            lbl.pack(side="right")
            self.services[svc] = var

        # Key metrics
        ttk.Label(sidebar, text="Key Metrics", font=("Arial", 12, "bold")).pack(anchor="w", pady=(8,2))
        self.metric_total = tk.IntVar(value=0); self.metric_high = tk.IntVar(value=0); self.metric_medium = tk.IntVar(value=0)
        ttk.Label(sidebar, text="Total Alerts:").pack(anchor="w"); ttk.Label(sidebar, textvariable=self.metric_total).pack(anchor="w")
        ttk.Label(sidebar, text="High Severity:").pack(anchor="w"); ttk.Label(sidebar, textvariable=self.metric_high).pack(anchor="w")
        ttk.Label(sidebar, text="Medium Severity:").pack(anchor="w"); ttk.Label(sidebar, textvariable=self.metric_medium).pack(anchor="w")

        # Center - chart + log
        center = ttk.Frame(body, padding=10); center.pack(side="left", fill="both", expand=True)
        self.fig, self.ax = plt.subplots(figsize=(5,3))
        self.times, self.counts = [], []
        self.canvas = FigureCanvasTkAgg(self.fig, master=center)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        ttk.Label(center, text="Event Log", font=("Arial", 12, "bold")).pack(anchor="w", pady=(8,0))
        self.log = ttk.Treeview(center, columns=("time","severity","msg"), show="headings", height=14)
        for c in ("time","severity","msg"):
            self.log.heading(c, text=c.title())
            self.log.column(c, width=200 if c=="msg" else 100, anchor="w")
        self.log.pack(fill="both", expand=True)

        # Right - assets
        right = ttk.Frame(body, padding=10); right.pack(side="right", fill="y")
        ttk.Label(right, text="Honeypot Assets", font=("Arial", 12, "bold")).pack(anchor="w")
        self.assets = ttk.Treeview(right, columns=("status","entropy"), show="headings", height=20)
        self.assets.heading("status", text="Status"); self.assets.heading("entropy", text="Entropy")
        self.assets.pack(fill="y")

        # initial population of assets
        try:
            files = os.listdir(HONEYPOT_PATH)
        except Exception:
            files = []
        for f in files:
            self.assets.insert("", "end", iid=f, values=("OK", f"{random.uniform(2.0,4.5):.2f}"))

        # monitor control
        self.monitor_thread = None
        self.monitor_stop_event = threading.Event()

        # start UI queue polling
        self.after(POLL_INTERVAL, self.process_events)

    # ---------------- UI actions ----------------
    def start_monitor(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            messagebox.showinfo("Info", "Monitor already running")
            return
        # change service status
        for k in self.services: self.services[k].set("Active")
        self.status_var.set("Running")
        self.metric_total.set(0); self.metric_high.set(0); self.metric_medium.set(0)
        # start monitor thread
        self.monitor_stop_event.clear()
        self.monitor_thread = threading.Thread(target=monitor_loop, args=(event_queue, self.monitor_stop_event, HONEYPOT_PATH), daemon=True)
        self.monitor_thread.start()
        event_queue.put({"time": time.time(), "type":"INFO", "severity":"LOW", "msg":"Monitor started", "asset": None})

    def stop_monitor(self):
        self.monitor_stop_event.set()
        for k in self.services: self.services[k].set("Stopped")
        self.status_var.set("Stopped")
        event_queue.put({"time": time.time(), "type":"INFO", "severity":"LOW", "msg":"Monitor stopped", "asset": None})

    def ui_simulate_attack(self):
        # ask user for level
        level = simpledialog.askstring("Simulate Attack", "Enter level (low/medium/high):", initialvalue="low")
        if not level: return
        level = level.strip().lower()
        if level == "low":
            n = attack_low(HONEYPOT_PATH)
            messagebox.showinfo("Attack", f"Low attack applied to {n} files.")
        elif level == "medium":
            n = attack_medium(HONEYPOT_PATH)
            messagebox.showinfo("Attack", f"Medium attack applied to {n} files.")
        elif level == "high":
            # confirm destructive action
            if messagebox.askyesno("Confirm", "High attack will XOR-encrypt files in honeypot (demo). Continue?"):
                n = attack_high(HONEYPOT_PATH)
                messagebox.showinfo("Attack", f"High attack applied to {n} files.")
        else:
            messagebox.showinfo("Attack", "Unknown level. Use low/medium/high.")

    def ui_restore_files(self):
        if messagebox.askyesno("Restore", "Attempt to restore files (XOR decrypt + revert .fake)?"):
            n = restore_files(HONEYPOT_PATH)
            messagebox.showinfo("Restore", f"Restore attempted on {n} files.")

    # ---------------- Event processing / UI update ----------------
    def process_events(self):
        updated = False
        while not event_queue.empty():
            ev = event_queue.get_nowait()
            ts = time.strftime("%H:%M:%S", time.localtime(ev.get("time", time.time())))
            self.log.insert("", "end", values=(ts, ev.get("severity",""), ev.get("msg","")))
            self.metric_total.set(self.metric_total.get() + 1)
            sev = ev.get("severity","")
            if sev == "HIGH":
                self.metric_high.set(self.metric_high.get() + 1)
            elif sev == "MEDIUM":
                self.metric_medium.set(self.metric_medium.get() + 1)
            asset = ev.get("asset")
            if asset and self.assets.exists(asset):
                self.assets.set(asset, "status", "ALERT")
                self.assets.set(asset, "entropy", f"{random.uniform(6.5,8.0):.2f}")
            elif asset and not self.assets.exists(asset):
                # new asset observed - add to tree
                try:
                    self.assets.insert("", "end", iid=asset, values=("ALERT", f"{random.uniform(6.5,8.0):.2f}"))
                except Exception:
                    pass
            updated = True

        if updated:
            now = time.time()
            self.times.append(now)
            self.counts.append(self.metric_total.get())
            if len(self.times) > 60:
                self.times = self.times[-60:]; self.counts = self.counts[-60:]
            self.ax.clear()
            start = self.times[0] if self.times else now
            x = [t - start for t in self.times]
            self.ax.plot(x, self.counts, marker="o")
            self.ax.set_xlabel("Seconds since start"); self.ax.set_ylabel("Alerts")
            try:
                self.canvas.draw_idle()
            except Exception:
                self.canvas.draw()

        self.after(POLL_INTERVAL, self.process_events)

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    # safety: ensure honeypot exists
    if not os.path.isdir(HONEYPOT_PATH):
        print(f"[Warning] HONEYPOT_PATH does not exist: {HONEYPOT_PATH}")
        print("Create the directory or update HONEYPOT_PATH before running.")
    app = HoneypotDashboard()
    app.mainloop()
