Tech Stack

Database/Storage: Yjs integrated with IndexedDB
Offline Support: Service Workers with Workbox.js
UI Framework: React
Encryption: AES-256 for data at rest and TLS 1.3 for data in transit
PWA: React PWA
Authentication: OAuth 2.0/OpenID Connect with JWTs
Build Tools: Vite
Data Sync & Versioning: GunDB
End-to-End Encryption: libsodium
CI/CD Pipeline: GitHub Actions

Reasoning:
Yjs provides efficient CRDT-based real-time collaboration.
IndexedDB complements Yjs for storing data locally with complex querying capabilities.
React offers a flexible and widely-supported UI framework.
Service Workers and Workbox.js ensure robust offline capabilities, essential for a PKM tool.
AES-256 and libsodium provide strong encryption standards for sensitive data.
OAuth 2.0/OpenID Connect with JWTs offers secure and scalable authentication and authorization.
Vite enhances development experience with fast build times.
GunDB adds decentralized data synchronization and Git-like versioning.
GitHub Actions simplifies the CI/CD pipeline with seamless GitHub integration.