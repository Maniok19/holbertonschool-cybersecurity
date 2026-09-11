# Executive Summary

ApexVault is engineered with a "Zero Trust, Zero Knowledge" security philosophy. The core architectural principle is that no single entity—not even ApexFin system administrators—can access client data, while every action taken on the system is cryptographically and immutably logged. By eliminating passwords and implementing client-side encryption, ApexVault ensures that even total server compromise does not result in data exposure or undetectable tampering.
## 1. Authentication Strategy

• Selected Technology: FIDO2 / WebAuthn Hardware Security Keys (e.g., YubiKey) combined with local biometric verification (Windows Hello / TouchID) for device unlock.

• Justification: FIDO2 is inherently un-phishable. Unlike passwords or SMS-based MFA (which are vulnerable to credential harvesting, SIM-swapping, and real-time relay attacks), FIDO2 uses public-key cryptography. The private key is mathematically bound to the physical hardware token and never leaves the device. The authentication protocol is also origin-bound, meaning a fake ApexVault website cannot trick the token into signing a challenge for the legitimate server. Even if a client is tricked into visiting a phishing site, the browser and hardware token will refuse to release the authentication credential.
## 2. Authorization Model

• Model Selected: Attribute-Based Access Control (ABAC) enforced through a Zero-Knowledge, Client-Side Encryption architecture.

• Admin Restriction: System Administrators (including root) are technically blocked from reading client files through Client-Side Encryption utilizing Hardware Security Modules (HSM).
Files are encrypted before they are transmitted to the ApexVault servers. The encryption keys are either held exclusively on the client's hardware token or wrapped by a dedicated HSM that enforces strict cryptographic policies. The server only ever stores and processes ciphertext. Therefore, a SysAdmin with root access can manage server resources (CPU, disk, network) but cannot decrypt or read the data—they only see meaningless cryptographic blobs. This is reinforced by strict MAC (Mandatory Access Control) policies like SELinux or AppArmor, which prevent the SysAdmin from dumping application memory or accessing the decryption keys in volatile storage.
## 3. Accounting Architecture

• Storage Location: Centralized, remote Write-Once-Read-Many (WORM) storage (e.g., AWS S3 Object Lock in Compliance Mode) paired with an isolated, air-gapped SIEM (Security Information and Event Management) server on a dedicated management VLAN.

• Integrity Mechanism: Cryptographic Hash Chaining and Immutable WORM Storage.
Every log entry contains a cryptographic hash of the previous entry, creating a blockchain-style ledger. If a hacker or malicious insider (like Bob) attempts to delete or modify a single log, the hash chain breaks, and the tampering is immediately detected by the SIEM. Furthermore, the logs are written to WORM storage configured with a strict retention policy (e.g., 365 days). This configuration makes it technically impossible for anyone—including root or the SysAdmin—to delete or alter logs before the retention period expires.