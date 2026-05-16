# Secure File Sharing System — Project Specification

---

## 1. Project Objective

Build a secure, end-to-end encrypted file sharing system based on a Client–Server model, running entirely on Docker. The core guarantee is **zero server knowledge**: all file content is encrypted on the client before transmission, and the server stores only ciphertext it cannot read. Only the intended recipients (individuals or group members) can decrypt received files.

---

## 2. System Architecture

The system is structured into **four components** across three Docker containers plus a terminal client.

### Node 1 — CA Server (PKI)
Handles all certificate operations:
- Generating RSA key pairs and issuing X.509 certificates for new users
- Maintaining the Certificate Revocation List (CRL)
- Providing a CRL distribution endpoint that clients and servers can fetch from
- Signing certificates through a two-tier chain: Root CA → Intermediate CA → User Certificate

### Node 2 — Auth Server (KDC / SSO)
Handles identity and session management:
- Accepting username and password at login
- Verifying the user's X.509 certificate against the CA chain and CRL before issuing a session ticket
- Issuing a signed Session Ticket (JWT-style, RSA-signed) that encodes the username, issue time, and expiry
- Maintaining a **Nonce Store** (small persistent database, e.g., SQLite) that records used nonces with their timestamps, to enable replay attack detection; nonces older than the configured TTL window (e.g., 5 minutes) are automatically purged

### Node 3 — File Server (Resource Server)
Handles all file and group operations:
- Storing encrypted file blobs, group metadata, and member lists
- Validating every incoming request by: (a) verifying the Session Ticket signature, (b) checking the nonce/timestamp pair against its own Nonce Store to reject replays
- Storing wrapped key material (File Session Keys encrypted per-recipient), but never holding plaintext keys or file content
- Providing a **Public Key Registry**: upon request, returns any user's X.509 certificate so the caller can extract their public key; the caller is responsible for verifying the certificate chain before trusting the key

### Client (Terminal App)
The only component that handles plaintext:
- All AES encryption and decryption of file content happens here
- Performs X.509 certificate chain verification before using any public key
- Manages the user's own private key and a local **encrypted key store** (see Section 4.3)
- Generates nonces and timestamps for every request sent to the File Server

---

## 3. Execution

The entire system runs via Docker Compose. A single `docker-compose up` command starts all three server containers. The client is a terminal application run separately (e.g., `python client.py`).

---

## 4. Cryptographic Design

### 4.1 Key Hierarchy

```
Root CA Key
  └── Intermediate CA Key
        └── User Certificate (RSA-2048 key pair, X.509)
                └── Group Master Key (AES-256, one per group)
                          └── File Session Key (AES-256, one per file upload)
                                    └── Encrypted File Content
```

### 4.2 File Upload Encryption Protocol

When a user uploads a file to share with a group or individual:

1. **Generate a File Session Key (FSK):** a fresh random AES-256 key, created for this file only.
2. **Encrypt the file content** with the FSK using AES-256-GCM. This produces the encrypted blob.
3. **Wrap the FSK:**
   - For a **group share**: retrieve the Group Master Key (GMK) from the local key store. Encrypt the FSK with the GMK (AES key wrapping, e.g., AES-KW or AES-GCM). The server receives one wrapped FSK that all current group members can unwrap using the GMK.
   - For an **individual share**: for each recipient, fetch their X.509 certificate from the File Server's Public Key Registry. Verify the certificate chain (Intermediate CA → Root CA) before proceeding. Extract the recipient's RSA public key. Encrypt the FSK with RSA-OAEP. The server receives one wrapped FSK per recipient.
4. **Upload** the encrypted blob and all wrapped FSK copies to the File Server. The server stores them but cannot read the FSK or the file content.

### 4.3 Group Master Key (GMK) Storage

The GMK is generated on the client at group creation time and must persist across sessions. It is **never sent to the server in plaintext**. Storage works as follows:

- The client derives a **Key Encryption Key (KEK)** from the user's password using PBKDF2 (or Argon2) with a per-user salt stored on the File Server.
- The GMK is encrypted with the KEK and stored as an encrypted blob on the File Server (one blob per user per group).
- At login, after receiving a valid Session Ticket, the client fetches its encrypted GMK blobs and decrypts them locally using the KEK derived from the entered password.
- This means the server holds encrypted GMKs but has no KEK, so it cannot derive the GMK.

### 4.4 Group Key Rotation (After Member Deletion)

When an administrator removes a member from a group, the GMK must be rotated so the removed member cannot decrypt future uploads:

1. The admin's client generates a new GMK v2 (random AES-256 key).
2. The client fetches the current member list from the File Server.
3. For each remaining member, the client fetches their X.509 certificate from the Public Key Registry, verifies the chain, and re-encrypts GMK v2 with that member's RSA public key (RSA-OAEP).
4. The client uploads all re-wrapped GMK v2 copies to the File Server in a single atomic operation, replacing the old GMK blobs.
5. The terminal prints: `Generating new Group Key v2... Redistributing key to N remaining members... Done.`
6. Files uploaded before the rotation remain encrypted under GMK v1; the deleted member retains access to those only. All new uploads use GMK v2.

### 4.5 Replay Attack Protection

Every request from the client to the File Server (and Auth Server) includes:
- A **Nonce**: a 128-bit random string, hex-encoded, unique per request.
- A **Timestamp**: ISO 8601 UTC timestamp of request creation.

The server checks:
1. The timestamp is within the acceptable window (e.g., ±5 minutes of server time).
2. The nonce has not been seen before (checked against the Nonce Store).

If either check fails, the server responds with `403 Replay Attack Detected: Nonce already used!` or `403 Request timestamp out of window.` and does not execute the request.

The Nonce Store persists to disk (survives container restarts) and automatically purges entries older than the TTL window.

### 4.6 X.509 Certificate Verification and MITM Protection

- Every client connection to any server verifies the server's TLS certificate against the CA chain. If the chain is invalid or untrusted, the client aborts: `Warning: Server certificate is invalid (Untrusted). Connection interrupted.`
- Before using any user's public key, the client retrieves and verifies that user's X.509 certificate: the certificate must be signed by the Intermediate CA, which must be signed by the Root CA, and must not appear on the current CRL.
- The CRL is fetched from the CA Server's distribution endpoint at login and cached for the session. Fetch failures are treated as errors (fail-closed, not fail-open).

---

## 5. User Registration and Certificate Issuance

When a new user selects "Register":

1. The client generates an RSA-2048 key pair locally.
2. The client sends a Certificate Signing Request (CSR) to the Auth Server, which acts as the Registration Authority (RA).
3. The RA forwards the CSR to the CA Server.
4. The CA Server validates the request, signs the certificate using the Intermediate CA key, and returns the certificate chain (`cert.pem`).
5. The Auth Server returns the certificate to the client, which stores it locally.
6. The terminal prints: `Certificate request sent to CA Server... Success!`

---

## 6. Login and SSO Flow

1. The user enters their username and password in the terminal.
2. The client connects to the Auth Server (verifying the server's certificate first).
3. The Auth Server looks up the user's certificate, verifies the chain and CRL status.
   - If the certificate is revoked: `Certificate revoked. Access denied.`
   - If the chain is invalid: authentication fails.
4. The Auth Server verifies the password hash.
5. On success, the Auth Server issues a **Session Ticket**: a signed JSON payload containing `{username, issued_at, expires_at}`, signed with the Auth Server's RSA private key.
6. The client stores the Session Ticket in memory for the duration of the session. All subsequent requests to the File Server include this ticket in the request header.
7. The File Server verifies the ticket signature using the Auth Server's public key (pre-shared at deployment). It does not contact the Auth Server again; it only checks the signature and expiry.
8. Audit log entry: `[AUTH] User 'username' logged in successfully. Ticket issued.`

---

## 7. Application UI — Screen Flows

### 7.1 Entry Screen

```
1. Login
2. Register
0. Exit
```

Username may contain only alphanumeric characters.

---

### 7.2 Main Menu

After login, the following menu is displayed. An asterisk (`*`) appears next to any section with pending items.

```
1. Pending Files (N*)
2. Upload File
3. My Groups (N*)
0. Logout
```

---

### 7.3 Pending Files

Displays a list of files that have been shared with the user and are ready to download.

**Columns:** #, Group / Sender, Sender Username, File Name, Uploaded At

Below the list:
```
Select file number to continue:
```

After selecting a file:
```
1. Download file
2. Delete file
0. Back
```

- **Download file:** the client fetches the encrypted blob and the wrapped FSK from the File Server. It decrypts the FSK (using either the GMK from the local key store, or the user's RSA private key for individual shares), then decrypts the file content. The file is saved to the user's specified local path. Upon successful download, the file is removed from the Pending Files list to save server storage.
- **Delete file:** removes the file from the Pending Files list without downloading. A confirmation prompt is shown first.

---

### 7.4 Upload File

**Step 1:**
```
1. Share with group
2. Share with individual
0. Back
```

**Step 2a — Share with group:** displays the list of groups the user belongs to. Prompts:
```
Enter group name or number:
```

**Step 2b — Share with individual:** prompts:
```
Enter recipient usernames (comma-separated, no spaces):
```

**Step 3:** prompts:
```
Enter path to file:
```

The client checks that the file exists at the given path. If not found, an error is shown and the user is returned to Step 3.

**Step 4:** if the file is found:
```
Upload '[filename]' to [target]? (Y/N):
```

If confirmed, the client performs the encryption protocol (Section 4.2) and uploads to the File Server. If cancelled: `File upload cancelled.` and returns to the main menu.

Audit log entry on success: `[FILE] User 'username' uploaded file 'filename' to Group/User 'target'.`

---

### 7.5 My Groups

```
1. View my groups
2. Group invitations (N*)
3. Create group
0. Back
```

#### View My Groups

Displays a table of groups the user belongs to.

**Columns:** #, Group Name, Admin Username, Created At, Member Count

Prompt:
```
Enter group name or number to continue:
```

After selecting a group, the following menu is shown. Options 2, 3, 5, 6, and 8 are visible only to the group admin. If a non-admin user presses a restricted option number, the system responds: `Access Denied: Only administrators can perform this action.`

```
1. View members
2. Add member          [admin only]
3. Remove member       [admin only]
4. Edit my display name
5. Edit group name     [admin only]
6. Transfer admin      [admin only]
7. Leave group
8. Delete group        [admin only]
0. Back
```

**View members:** displays member list with columns: #, Display Name, Username.

**Add member:** prompts for a username. The client fetches the target user's certificate, verifies the chain and CRL status, then prompts the File Server to add the user. The server also sends a group invitation to that user. The GMK is not redistributed at add time — the new member will receive it via their invitation acceptance flow (see Section 7.5, Group Invitations).

**Remove member:** prompts for a username. Confirms:
```
Remove 'username' from group? (Y/N):
```
On confirmation, triggers the key rotation protocol (Section 4.4). Returns to the group list after completion.

**Edit my display name:** prompts the user to enter a new display name for themselves within this group. Updates the File Server record.

**Edit group name:** prompts for a new group name (admin only). Updates the group record on the File Server.

**Transfer admin:** prompts for a username. Confirms:
```
Transfer admin rights to 'username'? (Y/N):
```
On confirmation, the target user becomes admin and the current user becomes a regular member.

**Leave group:** if the user is the admin and there are other members, they must first transfer admin rights before leaving. The system will prompt: `You are the admin. Transfer admin rights before leaving. Use option 6.` If the user is the only member, they may leave (which effectively deletes the group). Otherwise, confirms:
```
Leave group 'groupname'? (Y/N):
```

**Delete group:** admin only. Removes the group, all stored file blobs associated with it, and all member records. Confirms:
```
Delete group 'groupname' and all its files? This cannot be undone. (Y/N):
```

#### Group Invitations

Displays pending invitations.

**Columns:** #, Group Name, Admin Username

Prompt:
```
Select invitation number to continue:
```

After selecting:
```
Accept invitation to 'groupname'? (Y/N):
0. Back
```

If accepted:
```
Enter your display name in this group:
```

The client notifies the File Server, which delivers the GMK (encrypted with the new member's RSA public key) to the client. The client decrypts the GMK using its RSA private key, then re-encrypts it under the KEK and stores it in the local key store. The invitation is removed from the list.

If declined, the invitation is removed from the list without joining.

#### Create Group

Prompts:
```
Enter new group name:
```

The client generates a random AES-256 GMK, encrypts it under the user's KEK, and stores the encrypted blob on the File Server. The user is set as admin. Audit log entry: `[GROUP] User 'username' created group 'groupname'.`

---

## 8. Audit Logging

All significant events are appended to a persistent `audit_log.txt` file on the File Server (or a dedicated database table). Log entries follow this format:

```
[DD-MM-YYYY HH:MM:SS] [CATEGORY] Description
```

**Categories and example entries:**

```
[AUTH]  User 'nam_123' logged in successfully. Ticket issued.
[AUTH]  User 'nam_123' failed login (invalid password).
[AUTH]  User 'hacker_99' login rejected (certificate revoked).
[FILE]  User 'nam_123' uploaded file 'doc1.pdf' to Group 'Nhom_KMA'.
[FILE]  User 'nam_123' downloaded file 'doc1.pdf'.
[FILE]  User 'nam_123' deleted pending file 'doc1.pdf'.
[GROUP] User 'nam_123' created group 'Nhom_KMA'.
[GROUP] Admin 'nam_123' removed user 'user_456' from group 'Nhom_KMA'. Key rotated.
[GROUP] Admin 'nam_123' transferred admin rights to 'user_789' in group 'Nhom_KMA'.
[PKI]   CA Server issued certificate for user 'nam_123'.
[PKI]   CA Server revoked certificate for user 'hacker_99'. CRL updated.
[SECURITY] Replay attack detected: nonce 'abc123' already used. Request rejected.
```

---

## 9. Level Summary

| Level | Requirement | Implementation |
|---|---|---|
| Basic | AES-256 + RSA hybrid encryption | File Session Key encrypted with GMK or RSA public key; blobs encrypted with FSK |
| Basic | Key lifecycle (generation, rotation) | GMK generated at group creation; rotated with new member list re-encryption on member removal |
| Basic | Nonce + timestamp replay protection | All requests include nonce + timestamp; File Server validates against persistent Nonce Store |
| Basic | Public key source authentication | Public keys delivered via X.509 certificates; chain verified before use |
| Good | Master Key vs Session Key separation | GMK is master; FSK is per-file session key; FSK wrapped under GMK |
| Good | Identity-based access control | Admin-only actions enforced server-side; client-side enforcement is UI only |
| Good | X.509, CRL, MITM protection | Full chain validation on every cert; CRL checked at login; server cert verified on connect |
| Advanced | Three Docker containers (CA, Auth, File) | Separate containers with defined responsibilities |
| Advanced | PKI with certificate chain | Root CA → Intermediate CA → User cert; chain validated end-to-end |
| Advanced | SSO / Kerberos-like ticketing | Password entered once at Auth Server; signed Session Ticket used for all File Server requests |
| Advanced | Audit log | Persistent structured log on File Server covering auth, file, group, PKI, and security events |

---

## 10. Project Structure

```
project/
├── docker-compose.yml
├── ca_server/          # Node 1: CA Server (PKI)
│   ├── Dockerfile
│   ├── ca_server.py
│   ├── root_ca/        # Root CA key and cert (generated at first boot)
│   └── intermediate_ca/ # Intermediate CA key and cert
├── auth_server/        # Node 2: Auth Server (KDC)
│   ├── Dockerfile
│   ├── auth_server.py
│   └── nonce_store.db  # Persistent SQLite nonce store
├── file_server/        # Node 3: File Server (Resource)
│   ├── Dockerfile
│   ├── file_server.py
│   ├── audit_log.txt
│   ├── nonce_store.db  # Separate persistent nonce store
│   └── storage/        # Encrypted file blobs and wrapped keys
└── client/             # Terminal client app
    ├── client.py
    ├── local_keystore/  # Encrypted GMK blobs (KEK-encrypted, stored locally)
    └── certs/           # Cached server certs and CRL
```
