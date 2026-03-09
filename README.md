# Cryptography Labs — SOC Analyst Practical Writeup

**Author:** Guilherme Pigoso Garcia  
**Focus:** Junior SOC Analyst / Blue Team  
**Environment:** Kali Linux (VirtualBox)  
**Tools Used:** `sha256sum`, `openssl`, `cmp`, `echo`, VirusTotal  
**Framework Reference:** NIST SP 800-53 — SC-13 (Cryptographic Protection)

---

## Overview

This document covers three hands-on cryptography labs performed in a personal SOC home lab. The objective was to bridge theoretical knowledge (hashing, symmetric encryption, salting) with the practical skills used by a SOC Analyst during incident response, forensic investigations, and security assessments.

---

## Lab 1 — File Integrity Verification with SHA-256

### Objective
Demonstrate how hash functions are used to verify data integrity and detect file tampering — a core skill in digital forensics and malware analysis.

### Scenario
Two files appear visually identical. The goal is to determine whether they are truly identical using hash comparison.

### Commands Used

```bash
# Create working directory
mkdir ~/lab_crypto && cd ~/lab_crypto

# Create two files with subtle differences
echo "Este e o meu ficheiro original de teste SOC." > file1.txt
echo "Este e o meu ficheiro original de teste SOC." > file2.txt
echo "" >> file2.txt

# Generate SHA-256 hashes
sha256sum file1.txt
sha256sum file2.txt

# Save hashes to evidence files
sha256sum file1.txt >> file1.hash
sha256sum file2.txt >> file2.hash

# Compare hashes byte by byte
cmp file1.hash file2.hash
```

### Results

| File | SHA-256 Hash | Identical? |
|---|---|---|
| file1.txt | `131f95c51cc819...` | — |
| file2.txt | `2558ba9a4cad1e...` | ❌ Different |

- `cat` output: Both files appeared visually identical
- `sha256sum` output: Completely different hashes
- `cmp` output: `file1.hash file2.hash differ: char 1, line 1`

### Key Finding
A single invisible difference (blank line) produced completely different SHA-256 hashes. This demonstrates the **Avalanche Effect** — a fundamental property of cryptographic hash functions.

### SOC Analyst Takeaway
> Never trust visual inspection of files. Hash comparison is the only reliable method to confirm file integrity. In a real SOC environment, this workflow is automated via **File Integrity Monitoring (FIM)** tools such as Wazuh, Tripwire, or OSSEC.

---

## Lab 2 — Symmetric Encryption with OpenSSL AES-256-CBC

### Objective
Demonstrate the full encrypt/decrypt cycle using AES-256-CBC via OpenSSL, and verify data integrity post-decryption using SHA-256.

### Scenario
A sensitive file needs to be encrypted for secure storage or transmission. After decryption, integrity must be verified.

### Commands Used

```bash
# Encrypt file using AES-256-CBC
openssl aes-256-cbc -pbkdf2 -a -e \
  -in file1.txt \
  -out file1.encrypted \
  -k senhasecreta123

# Inspect encrypted output (unreadable ciphertext)
cat file1.encrypted

# Decrypt the file
openssl aes-256-cbc -pbkdf2 -a -d \
  -in file1.encrypted \
  -out file1.recovered \
  -k senhasecreta123

# Verify integrity — compare original vs recovered
sha256sum file1.txt
sha256sum file1.recovered
```

### Command Breakdown

| Parameter | Meaning |
|---|---|
| `openssl` | Cryptographic toolkit |
| `aes-256-cbc` | AES algorithm, 256-bit key, CBC mode |
| `-pbkdf2` | Strengthens password into a cryptographic key |
| `-a` | Base64 output encoding |
| `-e` | Encrypt mode |
| `-d` | Decrypt mode |
| `-in` | Input file |
| `-out` | Output file |
| `-k` | Password/key |

### Results

- Encrypted file: unreadable ciphertext (Base64 encoded)
- Decryption: successful — original content recovered
- Hash comparison: **identical hashes** between `file1.txt` and `file1.recovered`

### Key Finding
Identical SHA-256 hashes between the original and recovered file **prove data integrity** — no bits were corrupted or modified during the encryption/decryption process.

### SOC Analyst Takeaway
> AES-256-CBC is the industry standard for symmetric encryption. In enterprise environments it is used for encrypting data at rest (databases, backups) and data in transit (VPN tunnels). The `-pbkdf2` flag is critical — without it, weak passwords are vulnerable to brute force attacks against the key derivation.

---

## Lab 3 — Password Salting vs Rainbow Table Attacks

### Objective
Demonstrate the vulnerability of unsalted password hashes to Rainbow Table attacks, and how salting neutralises this attack vector.

### Scenario
Three users share the same password. Compare hash storage with and without salt to understand the security implications.

### Commands Used

```bash
mkdir salting_lab && cd salting_lab

# --- WITHOUT SALT ---
# Generate hashes for identical passwords
HASH1=$(echo -n "password123" | sha256sum)
echo "user1:$HASH1" >> db_sem_salt.txt

HASH2=$(echo -n "password123" | sha256sum)
echo "user2:$HASH2" >> db_sem_salt.txt

HASH3=$(echo -n "password123" | sha256sum)
echo "user3:$HASH3" >> db_sem_salt.txt

cat db_sem_salt.txt

# --- WITH SALT ---
# Generate unique random salts per user
SALT1=$(openssl rand -hex 16)
SALT2=$(openssl rand -hex 16)
SALT3=$(openssl rand -hex 16)

# Apply salt before hashing
HASH1=$(echo -n "${SALT1}password123" | sha256sum)
echo "user1:$SALT1:$HASH1" >> db_com_salt.txt

HASH2=$(echo -n "${SALT2}password123" | sha256sum)
echo "user2:$SALT2:$HASH2" >> db_com_salt.txt

HASH3=$(echo -n "${SALT3}password123" | sha256sum)
echo "user3:$SALT3:$HASH3" >> db_com_salt.txt

cat db_com_salt.txt
```

### Results

**Without Salt — all hashes identical:**
```
user1: a665a45920422f...  ← same
user2: a665a45920422f...  ← same
user3: a665a45920422f...  ← same
```

**With Salt — all hashes unique:**
```
user1: [salt1]: 9f3a2c17eb4...  ← unique
user2: [salt2]: 4d8b1a93fc2...  ← unique
user3: [salt3]: 7e2f5d84ab1...  ← unique
```

### Key Finding
Same password, completely different hashes when salt is applied. A Rainbow Table attack pre-computes hashes for common passwords — salting renders these pre-computed tables useless because the attacker would need a separate Rainbow Table for every unique salt.

### SOC Analyst Takeaway
> During security audits or post-breach investigations, identifying unsalted MD5 or SHA-1 password hashes in a database is a **critical finding**. Under GDPR (applicable in Portugal and the EU), storing passwords without adequate cryptographic protection is a compliance violation that must be reported and remediated immediately. Recommendation: SHA-256 or SHA-512 with unique per-user salt, or modern purpose-built functions such as bcrypt or Argon2.

---

## Lab 4 — Malware Hash Analysis & VirusTotal Workflow

### Objective
Simulate the real SOC analyst workflow for investigating a suspicious file using hash-based threat intelligence — without executing the file.

### Scenario
A suspicious file is identified on an endpoint. Standard procedure: generate hash → query threat intelligence platform → document findings as IOC.

### Commands Used

```bash
mkdir malware_lab && cd malware_lab

# Create EICAR standard antivirus test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt

# Create a legitimate file for comparison
echo "Este e um ficheiro legitimo do sistema." > legitimo.txt

# Generate SHA-256 hashes
sha256sum eicar.txt
sha256sum legitimo.txt

# Save hashes as forensic evidence record
sha256sum eicar.txt >> evidencias.txt
sha256sum legitimo.txt >> evidencias.txt

# Simulate file tampering
echo "modificacao" >> eicar.txt
sha256sum eicar.txt >> evidencias_pos_modificacao.txt

# Compare pre and post-modification hashes
cmp evidencias.txt evidencias_pos_modificacao.txt
```

### VirusTotal Results

| File | VirusTotal Result | Detection Rate |
|---|---|---|
| eicar.txt | ✅ Detected — EICAR Test File | 62/68 engines |
| legitimo.txt | ⚪ No reports found | 0/68 engines |
| eicar.txt (modified) | Hash changed — new unknown sample | N/A |

### SOC Analyst Workflow Demonstrated

```
Suspicious file identified on endpoint
            ↓
sha256sum ficheiro_suspeito → generate hash
            ↓
Query hash on VirusTotal / MalwareBazaar
            ↓
[KNOWN MALWARE] → P1 Incident Response
[UNKNOWN]       → Submit to sandbox (Any.run / Hybrid Analysis)
            ↓
Document hash as IOC in incident report
            ↓
Threat Intelligence sharing with team
```

### Key Finding
- EICAR detected by 62/68 AV engines — clear malicious indicator
- Legitimate file returned no results — unknown ≠ safe, requires further analysis
- Post-modification hash completely different — confirmed Avalanche Effect and tamper detection capability

### SOC Analyst Takeaway
> Hash-based threat intelligence is the fastest triage method available to a SOC analyst. It requires no execution of the suspicious file, produces immediate results, and generates documented IOCs. In enterprise environments, this workflow is integrated into SIEM platforms (Splunk, Microsoft Sentinel) via threat intelligence feeds such as AlienVault OTX, MalwareBazaar, and VirusTotal Enterprise API.

---

## Summary — Skills Demonstrated

| Skill | Tool | Lab |
|---|---|---|
| File Integrity Verification | `sha256sum`, `cmp` | Lab 1 |
| Symmetric Encryption/Decryption | `openssl aes-256-cbc` | Lab 2 |
| Password Security & Salting | `sha256sum`, `openssl rand` | Lab 3 |
| Malware Triage via Hash Analysis | `sha256sum`, VirusTotal | Lab 4 |
| Forensic Evidence Documentation | `>>`, `cat` | All Labs |
| Linux CLI Navigation | `mkdir`, `cd`, `cat`, `echo` | All Labs |

---

## References

- NIST SP 800-53 — SC-13: Cryptographic Protection
- NIST FIPS 180-4 — Secure Hash Standard (SHA)
- GDPR Article 32 — Security of Processing
- VirusTotal: https://www.virustotal.com
- EICAR Standard: https://www.eicar.org

---

*Lab environment: Kali Linux on VirtualBox | Date: 2026*  
*GitHub: https://github.com/GPigoso*
