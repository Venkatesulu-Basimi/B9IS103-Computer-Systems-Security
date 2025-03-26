# Encrypted Communications Application
COverview
This project is an encrypted communications/collaboration application that ensures secure and private communication between users. The application leverages modern cryptographic techniques to provide end-to-end encryption without storing private and public keys in a database. Users' messages are encrypted using Public Key Infrastructure (PKI), ensuring that only the intended recipient can read the message.

The application uses a Flask server as a relay for managing user interactions, handling encryption and decryption processes, and ensuring system integrity. Flask is chosen for its simplicity and flexibility, enabling quick development and deployment.

Features
End-to-End Encryption: Ensures that only the intended recipient can decrypt and read the message.

Private Key Management: No private/public keys are stored in a database, enhancing security.

User Authentication: Secure login and email verification for new users.

Message Integrity: Prevents unauthorized access or tampering with messages.

Scalable Architecture: Built with scalability in mind to support future growth.

System Architecture
The system architecture revolves around a Flask server that handles all user interactions, including encryption and decryption processes. The application uses Public Key Infrastructure (PKI) to ensure messages are only readable by their intended recipients.

Encryption Process:
Messages are encrypted using the recipient's public key.

Only the recipient can decrypt the message using their corresponding private key.

The system ensures that keys are never stored in a database, offering an additional layer of security.
