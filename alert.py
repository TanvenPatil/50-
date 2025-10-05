import os
import time
import hashlib
import math
import logging
from collections import deque

#   pip install psutil
# Email uses smtplib (built-in)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

try:
    import psutil
except ImportError:
    psutil = None

# --- Windows popup (no install needed) ---
import ctypes
def play_beep(seconds=5, freq=1000, dur=300):
    """
    Play a beep pattern for `seconds` seconds.
    Uses winsound on Windows if available; otherwise prints terminal bell.
    This function blocks — start it in a Thread if you want non-blocking behavior.
    """
    try:
        import winsound
    except Exception:
        winsound = None

    end = time.time() + seconds
    if winsound:
        # continuous beep (winsound.Beep blocks for each call)
        while time.time() < end:
            try:
                winsound.Beep(freq, dur)
            except Exception:
                # some environments may raise if audio not available
                print("\a", end="", flush=True)
                time.sleep(dur/1000.0)
    else:
        # fallback: terminal bell repeatedly
        while time.time() < end:
            print("\a", end="", flush=True)
            time.sleep(0.4)



# CONFIG
HONEYPOT_FOLDER = r"C:\Users\tanve.PREDATOR\OneDrive\Desktop\Ransomware\honeypot"

CHECK_INTERVAL = 2              # seconds between scans
ACCESS_WINDOW = 10              # seconds to measure access frequency
ACCESS_THRESHOLD = 5            # files accessed within window => suspicious
ENTROPY_SUSPECT = 7.5           # 0..8 ; >7.5 looks like encrypted content

# Actions (toggle as you like)
ENABLE_POPUP = True
ENABLE_EMAIL = True            # set True after filling SMTP settings below
ENABLE_KILL  = False             # try to kill processes touching honeypot
ENABLE_SHUTDOWN = False         # last resort; needs admin

# Email settings (only if ENABLE_EMAIL = True)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "tanvenpatil1510@gmail.com"
SMTP_PASS = "lkql peht joei rtsk"   # Use an APP PASSWORD (not your real password)
EMAIL_TO  = "tanvenpatil1510@gmail.com"

# Logging
LOG_FILE = "honeypot_alerts.log"

# LOGGING
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

def log_both(message, level="warning"):
    """Print to console and write to log file."""
    print(message)
    getattr(logging, level, logging.warning)(message)


# UTIL: POPUP / EMAIL / KILL / SHUTDOWN
def popup_alert(title, message):
    if not ENABLE_POPUP:
        return
    try:
        # 0x10 = MB_ICONHAND (red stop icon)
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
    except Exception as e:
        log_both(f"Popup failed: {e}", "error")

def send_email(subject, body):
    if not ENABLE_EMAIL:
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = EMAIL_TO
        msg["Subject"] = "HoneyPot Alert"
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        log_both("Email sent.", "info")
    except Exception as e:
        log_both(f"Email failed: {e}", "error")

def kill_offending_processes(honeypot_root):
    """Terminate any process that currently has files open under the honeypot."""
    if not ENABLE_KILL:
        return
    if psutil is None:
        log_both("psutil not installed; cannot kill processes. Run: pip install psutil", "error")
        return

    killed = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            files = proc.open_files()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception:
            continue

        for f in files:
            # If this open file path is inside the honeypot, terminate the process
            if f.path and os.path.commonpath([honeypot_root, f.path]) == honeypot_root:
                try:
                    log_both(f"Attempting to terminate PID {proc.pid} ({proc.info.get('name')}) due to access: {f.path}", "warning")
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    killed.append(proc.pid)
                    break
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    log_both(f"Failed to terminate PID {proc.pid}: {e}", "error")
                except Exception as e:
                    log_both(f"Terminate error PID {proc.pid}: {e}", "error")

    if killed:
        log_both(f"Terminated processes: {killed}", "info")
    else:
        log_both(" No processes with open honeypot files were terminated.", "info")

def emergency_shutdown():
    if not ENABLE_SHUTDOWN:
        return
    try:
        # Immediate shutdown (Windows)
        os.system("shutdown /s /t 0")
    except Exception as e:
        log_both(f"Shutdown failed: {e}", "error")

def respond_to_attack(reason, evidence_path=None):
    """Central handler when suspicious behavior is detected."""
    title = "HONEYPOT ALERT – Possible Ransomware!"
    lines = [f"Reason: {reason}"]
    if evidence_path:
        lines.append(f"Evidence: {evidence_path}")
    lines.append(f"Folder: {HONEYPOT_FOLDER}")
    body = "\n".join(lines)

    # --- classify severity from reason text (simple keyword rules) ---
    rl = (reason or "").lower()
    severity = "LOW"
    if any(k in rl for k in ("entropy", "encryption", "encrypted", "high entropy", "likely encryption")):
        severity = "HIGH"
    elif any(k in rl for k in ("deleted", "burst", "access", "suspicious", "suspicious extension", ".locked", ".enc", ".crypt")):
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # --- choose beep pattern per severity ---
    # MEDIUM: 5 seconds (user requested 5s)
    # HIGH: 5 seconds, higher pitch / same length (distinct tone)
    # LOW: short single beep (non-intrusive)
    if severity == "HIGH":
        beep_args = (5, 1200, 300)   # seconds, freq, dur(ms)
    elif severity == "MEDIUM":
        beep_args = (5, 800, 300)    # 5s, lower tone
    else:  # LOW
        beep_args = (1, 600, 400)    # short 1s beep

    # start beep in background so UI / monitor is not blocked
    try:
        t = threading.Thread(target=play_beep, args=beep_args, daemon=True)
        t.start()
    except Exception as e:
        log_both(f"Failed to start beep thread: {e}", "error")

    # Log + popup + email (existing behavior)
    log_both(f"{title}\nSeverity: {severity}\n{body}\n", "critical")
    popup_alert(f"{title} ({severity})", body)
    send_email(f"{title} ({severity})", body)

    # Active response (respects ENABLE_KILL / ENABLE_SHUTDOWN flags already in your code)
    kill_offending_processes(os.path.abspath(HONEYPOT_FOLDER))
    emergency_shutdown()

# DETECTION (from Step 3)
recent_accesses = deque()

def calculate_entropy(data):
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
        # sample first 1KB for speed; adjust if you want deeper scan
        with open(path, "rb") as f:
            sample = f.read(1024)
        return {
            "hash": hashlib.md5(sample).hexdigest(),
            "access_time": st.st_atime,
            "entropy": calculate_entropy(sample)
        }
    except Exception:
        return None

def load_file_states():
    state = {}
    for root, _, files in os.walk(HONEYPOT_FOLDER):
        for name in files:
            p = os.path.join(root, name)
            info = get_file_info(p)
            if info is not None:
                state[p] = info
    return state

def monitor():
    log_both("Honeypot monitor + alert/response started...", "info")
    prev = load_file_states()

    while True:
        time.sleep(CHECK_INTERVAL)
        curr = load_file_states()

        # Deleted / modified / access frequency / entropy spike
        for path, old in prev.items():
            if path not in curr:
                log_both(f"File deleted: {path}")
                respond_to_attack("File deleted in honeypot", path)
                continue

            new = curr[path]
            # Modified?
            if new["hash"] != old["hash"]:
                log_both(f"File modified: {path}")
                # Entropy check
                if new["entropy"] > ENTROPY_SUSPECT:
                    log_both(f" High entropy (possible encryption): {path}")
                    respond_to_attack("High-entropy modification (likely encryption)", path)

            # Access frequency (best-effort)
            if new["access_time"] != old["access_time"]:
                recent_accesses.append(time.time())
                while recent_accesses and time.time() - recent_accesses[0] > ACCESS_WINDOW:
                    recent_accesses.popleft()
                if len(recent_accesses) >= ACCESS_THRESHOLD:
                    log_both(f"High access frequency ({len(recent_accesses)} in {ACCESS_WINDOW}s)")
                    respond_to_attack("Burst of file accesses", path)
                    recent_accesses.clear()  # avoid repeated storms

        # New files + suspicious extensions
        for path in curr:
            if path not in prev:
                log_both(f" New file created: {path}")
                lower = path.lower()
                if lower.endswith((".locked", ".crypt", ".enc", ".encrypted")):
                    log_both(f"Suspicious extension: {path}")
                    respond_to_attack("Suspicious ransomware-style extension", path)

        prev = curr

# MAIN
if __name__ == "__main__":
    # Safety: warn if powerful actions are enabled
    if ENABLE_SHUTDOWN:
        log_both("System will SHUT DOWN on detection (ENABLE_SHUTDOWN=True).", "warning")
    if ENABLE_KILL and psutil is None:
        log_both("ENABLE_KILL=True but psutil not installed. Run: pip install psutil", "warning")
    monitor()
