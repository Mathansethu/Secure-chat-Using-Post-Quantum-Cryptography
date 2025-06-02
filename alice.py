import socket
import threading
import tkinter as tk
from crypto_utils import kyber_key_exchange, decrypt_message, verify_signature, generate_dilithium_keys, encrypt_message, sign_message
from colorama import Fore, init

init(autoreset=True)

HOST = '127.0.0.1'
PORT = 65432

# Create Alice's window
alice_window = tk.Tk()
alice_window.title("Alice - Secure Chat (PQC)")

text_area = tk.Text(alice_window, height=20, width=50)
text_area.pack()

entry = tk.Entry(alice_window, width=40)
entry.pack()

send_button = tk.Button(alice_window, text="Send")
send_button.pack()

def display_message(msg):
    text_area.insert(tk.END, msg + "\n")
    text_area.see(tk.END)

# Setup Server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

display_message("[+] Waiting for Bob...")

conn, addr = server_socket.accept()
display_message(f"[+] Connected to {addr}")

# Kyber Key Exchange
alice_kem, alice_public_key = kyber_key_exchange()
conn.sendall(alice_public_key)

ciphertext = conn.recv(4096)
shared_secret = alice_kem.decap_secret(ciphertext)

print(Fore.CYAN + "[Alice Backend] Kyber Shared Secret Established.")
print(Fore.YELLOW + shared_secret.hex())

# Dilithium Key Generation
alice_signer, alice_dilithium_public_key = generate_dilithium_keys()
conn.sendall(alice_dilithium_public_key)

bob_dilithium_public_key = conn.recv(4096)

def receive_messages():
    while True:
        try:
            data = conn.recv(8192)
            if not data:
                break
            signature, encrypted = data.split(b'||')
            if verify_signature(bob_dilithium_public_key, encrypted, signature):
                plaintext = decrypt_message(shared_secret[:32], encrypted)
                display_message("[Bob]: " + plaintext)
                print(Fore.GREEN + "[Alice Backend] Dilithium2 Signature Verified ✅")
                print(Fore.CYAN + "[Alice Backend] Message Decrypted ✅")
            else:
                display_message("[!] Signature verification failed.")
                print(Fore.RED + "[Alice Backend] Dilithium2 Signature Verification ❌ FAILED!")
        except Exception as e:
            display_message(f"[!] Error: {e}")
            print(Fore.RED + f"[Alice Backend] Error: {e}")
            break

def send_message():
    message = entry.get()
    if message:
        encrypted = encrypt_message(shared_secret[:32], message)
        signature = sign_message(alice_signer, encrypted)
        conn.sendall(signature + b'||' + encrypted)
        display_message("[You]: " + message)
        print(Fore.CYAN + "[Alice Backend] Message Signed with Dilithium2 and Sent ✅")
        entry.delete(0, tk.END)

send_button.config(command=send_message)

threading.Thread(target=receive_messages, daemon=True).start()

alice_window.mainloop()
conn.close()
server_socket.close()
