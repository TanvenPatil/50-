import os
import time
import hashlib

#Path of honeypot folder (change if needed)
HONEYPOT_FOLDER = "honeypot"

#MAKES HONEY POT FILES
if not os.path.exists(HONEYPOT_FOLDER):
    os.makedirs(HONEYPOT_FOLDER)

for i in range(5):  #Create 5 honeypot files
    filepath = os.path.join(HONEYPOT_FOLDER, f"honey{i}") 
    if not os.path.exists(filepath):   #jar nasel tar
        with open(filepath, "w") as f: 
            f.write("Baghu Naka PLizzzz\n")  #dummy text inside

#Function to calculate file hash MD5

def get_file_hash(path):
    """Return MD5 hash (fingerprint) of a file's content."""
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None  #File may be deleted or inaccessible


#Load all files into a dictionary

def load_file_states():
    """Store current state of all files in honeypot folder."""
    file_states = {}
    for root, dirs, files in os.walk(HONEYPOT_FOLDER):
        for file in files:
            path = os.path.join(root, file)
            file_states[path] = get_file_hash(path)
    return file_states

#Monitor loop

def monitor_changes():
    print("🚨 Monitoring honeypot folder for ransomware activity...")
    previous_state = load_file_states()
 
    while True:
        time.sleep(2)  #Wait before checking again
        current_state = load_file_states()
        
        #Detect deleted or modified files
        for file, old_hash in previous_state.items():
            if file not in current_state:
                print(f"⚠️ ALERT: File deleted → {file}")
            elif current_state[file] != old_hash:
                print(f"⚠️ ALERT: File modified → {file}")
        
        #Detect new files
        for file in current_state:
            if file not in previous_state:
                print(f"⚠️ ALERT: New file created → {file}")
        
        #Update for next loop
        previous_state = current_state.copy()


#Main entry
if __name__ == "__main__":
    # Create honeypot folder if it doesn’t exist
    if not os.path.exists(HONEYPOT_FOLDER):
        os.makedirs(HONEYPOT_FOLDER)
        print(f"📂 Honeypot folder created at: {HONEYPOT_FOLDER}")
    try:
     monitor_changes()
    except KeyboardInterrupt:            #to avoid uneccesary error text after stopping the code (Ctrl+C)
       print("\n🛑 Monitoring stopped by user.")

   
