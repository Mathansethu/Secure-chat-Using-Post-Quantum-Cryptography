# Secure-chat-Using-Post-Quantum-Cryptography

Secure Chat using Post-Quantum Cryptography (PQC)

This project demonstrates a secure real-time chat application that uses Post-Quantum Cryptography (PQC) to protect communications against potential quantum attacks. It combines CRYSTALS-Kyber for key exchange, AES-256 for symmetric encryption, and CRYSTALS-Dilithium for digital signatures.

🚀 Features
🔐 Quantum-Resistant Key Exchange using CRYSTALS-Kyber (Kyber512)

🛡️ Message Encryption & Decryption with AES-256

✍️ Digital Signatures via CRYSTALS-Dilithium (Dilithium2)

✅ Integrity Assurance: Detects message tampering

💬 Real-Time Communication through WebSockets

⚙️ Backend: FastAPI (Python) with integrated PQC logic


🛠️ Technologies Used
Post-Quantum Algorithms: liboqs via oqs-python
Symmetric Encryption: AES-256 (via cryptography or pycryptodome)
Web Framework: FastAPI (Python)
WebSocket: For real-time messaging
Frontend: HTML, CSS, JavaScript
Deployment: Localhost / Docker-ready



🛡️ Why Post-Quantum?

Traditional public-key cryptography (RSA, ECC) is vulnerable to quantum attacks (e.g., Shor’s algorithm). This system adopts NIST-recommended algorithms to ensure forward secrecy and quantum resistance, protecting against future threats.

🔮 Future Improvements

Mobile version (React Native / Flutter)
Group chat with session key management
File transfer with encryption/signature
Docker support for deployment
Integration with decentralized identities (DID)

📄 License
MIT License. See LICENSE for details.

