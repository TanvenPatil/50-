import os
import time
import hashlib
import math
import logging
from collections import deque
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore, Style
from plyer import notification
import winsound  # Windows sound alert

# Initialize colorama
init(autoreset=True)

HONEYPOT_FOLDER = r"C:\Users\tanve.PREDATOR\OneDrive\Desktop\Ransomware\honeypot"
ACCESS_WINDOW = 10
ACCESS_THRESHOLD = 5

recent_accesses = deque()

# Setup logging
logging.basicConfig(
    filename="honeypot_alerts.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# Colored logging
def log_alert(message, risk="Low"):
    """Log to console with color and also to file"""
    if risk == "Low":
        print(Fore.GREEN + message)
    elif risk == "Medium":
        print(Fore.YELLOW + message)
    elif risk == "High":
        print(Fore.RED + message)
    logging.warning(message)

# Desktop and sound alert for high risk
def alert_user_high_risk(path):
    # Pop-up notification
    notification.notify(
        title="HIGH RISK ALERT!",
        message=f"Immediate action required for: {path}",
        timeout=5  # seconds
    )
    # Sound alert
    duration = 1000  # milliseconds
    freq = 1000  # Hz
    winsound.Beep(freq, duration)

# Entropy calculation
def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0]*256
    for b in data:
        byte_counts[b] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

# File info
def get_file_info(path):
    try:
        stats = os.stat(path)
        with open(path, "rb") as f:
            data = f.read(1024)  # sample first 1KB
        return {
            'hash': hashlib.md5(data).hexdigest(),
            'access_time': stats.st_atime,
            'entropy': calculate_entropy(data),
            'size': stats.st_size
        }
    except:
        return None

# Get process info
def get_suspicious_process_info():
    processes = []
    try:
        for proc in psutil.process_iter(attrs=["pid","name","exe"]):
            with proc.oneshot():
                pid = proc.info["pid"]
                name = proc.info["name"]
                exe = proc.info.get("exe","Unknown")
                try:
                    for f in proc.open_files():
                        if HONEYPOT_FOLDER.lower() in f.path.lower():
                            processes.append(f"PID={pid}, Name={name}, Path={exe}")
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
    except:
        pass
    return processes if processes else ["Unknown process"]

# Risk classification
def classify_risk(curr_info, old_info, path, recent_accesses):
    risk = "Low"

    if curr_info:
        # Medium risk
        if curr_info['size'] > (old_info['size']*2 if old_info else 0):
            risk = "Medium"
        if any(ext in path.lower() for ext in [".locked",".crypt",".enc",".encrypted"]):
            risk = "Medium"
        if curr_info['access_time'] != (old_info['access_time'] if old_info else 0):
            if len(recent_accesses) >= ACCESS_THRESHOLD:
                risk = "Medium"

    # High risk
    if curr_info and curr_info['entropy'] > 7.5:
        risk = "High"
    if risk=="Medium" and curr_info and curr_info['entropy']>7.5:
        risk = "High"

    return risk

# Event handler
class HoneypotHandler(FileSystemEventHandler):
    def __init__(self, previous_state):
        super().__init__()
        self.previous_state = previous_state

    def process_event(self, event, event_type):
        path = event.src_path
        if not os.path.isfile(path):
            return
        
        curr_info = get_file_info(path)
        old_info = self.previous_state.get(path)
        processes = get_suspicious_process_info()

        # Track access frequency
        if curr_info and curr_info['access_time'] != (old_info['access_time'] if old_info else 0):
            recent_accesses.append(time.time())
            while recent_accesses and time.time() - recent_accesses[0] > ACCESS_WINDOW:
                recent_accesses.popleft()

        # Risk classification
        risk = classify_risk(curr_info, old_info, path, recent_accesses)

        # Display risk and take action
        if risk == "Low":
            log_alert(f"LOW Risk: {event_type} detected: {path} | Process: {processes}", risk)
        elif risk == "Medium":
            log_alert(f"MEDIUM Risk: Suspicious activity detected: {path} | Process: {processes}", risk)
        elif risk == "High":
            log_alert(f"HIGH RISK: Immediate action required for: {path} | Process: {processes}", risk)
            # Immediate action: move to quarantine
            quarantine_folder = os.path.join(HONEYPOT_FOLDER, "Quarantine")
            os.makedirs(quarantine_folder, exist_ok=True)
            try:
                os.rename(path, os.path.join(quarantine_folder, os.path.basename(path)))
                log_alert(f"File moved to quarantine: {path}", risk)
            except Exception as e:
                log_alert(f"Failed to move file to quarantine: {e}", risk)
            # Pop-up & sound alert
            alert_user_high_risk(path)

        # Update state
        if curr_info:
            self.previous_state[path] = curr_info

    def on_created(self, event):
        self.process_event(event, "created")
    def on_deleted(self, event):
        self.process_event(event, "deleted")
    def on_modified(self, event):
        self.process_event(event, "modified")

# Load existing files
def load_file_states():
    file_states = {}
    for root, _, files in os.walk(HONEYPOT_FOLDER):
        for file in files:
            path = os.path.join(root, file)
            file_states[path] = get_file_info(path)
    return file_states

# Run honeypot
def run_honeypot():
    log_alert("Honeypot started with real-time risk classification...")
    previous_state = load_file_states()

    event_handler = HoneypotHandler(previous_state)
    observer = Observer()
    observer.schedule(event_handler, HONEYPOT_FOLDER, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    run_honeypot()

    try:
     run_honeypot()
    except KeyboardInterrupt:            #to avoid uneccesary error text after stopping the code (Ctrl+C)
       print("\n🛑 Monitoring stopped by user.")