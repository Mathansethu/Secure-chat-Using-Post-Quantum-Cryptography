import socket
import threading
import tkinter as tk
from crypto_utils import kyber_encapsulate, encrypt_message, sign_message, generate_dilithium_keys, decrypt_message, verify_signature
from colorama import Fore, init

init(autoreset=True)

HOST = '127.0.0.1'
PORT = 65432

bob_window = tk.Tk()
bob_window.title("Bob - Secure Chat (PQC)")

text_area = tk.Text(bob_window, height=20, width=50)
text_area.pack()

entry = tk.Entry(bob_window, width=40)
entry.pack()

send_button = tk.Button(bob_window, text="Send")
send_button.pack()

def display_message(msg):
    text_area.insert(tk.END, msg + "\n")
    text_area.see(tk.END)

# Setup Client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

alice_public_key = client_socket.recv(4096)

# Kyber Encapsulation
bob_kem, ciphertext, shared_secret = kyber_encapsulate(alice_public_key)
client_socket.sendall(ciphertext)

print(Fore.CYAN + "[Bob Backend] Kyber Shared Secret Established.")
print(Fore.YELLOW + shared_secret.hex())

# Dilithium Key Generation
bob_signer, bob_dilithium_public_key = generate_dilithium_keys()
client_socket.sendall(bob_dilithium_public_key)

alice_dilithium_public_key = client_socket.recv(4096)

def receive_messages():
    while True:
        try:
            data = client_socket.recv(8192)
            if not data:
                break
            signature, encrypted = data.split(b'||')
            if verify_signature(alice_dilithium_public_key, encrypted, signature):
                plaintext = decrypt_message(shared_secret[:32], encrypted)
                display_message("[Alice]: " + plaintext)
                print(Fore.GREEN + "[Bob Backend] Dilithium2 Signature Verified ✅")
                print(Fore.CYAN + "[Bob Backend] Message Decrypted ✅")
            else:
                display_message("[!] Signature verification failed.")
                print(Fore.RED + "[Bob Backend] Dilithium2 Signature Verification ❌ FAILED!")
        except Exception as e:
            display_message(f"[!] Error: {e}")
            print(Fore.RED + f"[Bob Backend] Error: {e}")
            break

def send_message():
    message = entry.get()
    if message:
        encrypted = encrypt_message(shared_secret[:32], message)
        signature = sign_message(bob_signer, encrypted)
        client_socket.sendall(signature + b'||' + encrypted)
        display_message("[You]: " + message)
        print(Fore.CYAN + "[Bob Backend] Message Signed with Dilithium2 and Sent ✅")
        entry.delete(0, tk.END)

send_button.config(command=send_message)

threading.Thread(target=receive_messages, daemon=True).start()

bob_window.mainloop()
client_socket.close()
