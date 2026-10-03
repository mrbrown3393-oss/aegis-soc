# MongoDB Encryption at Rest & TLS — Enablement Guide

This guide enables **WiredTiger native encryption (AES-256-GCM)** and **mandatory TLS** for all database communication, per policies AEG-DP-001 and AEG-CR-001.

## 1. Generate key material

```bash
bash deploy/mongodb/generate-keys.sh /secure/keys /secure/tls
```

- Store the encryption keyfile in your secrets manager / KMIP. Never commit it; it is ignored via `.gitignore` rules for `keys/` and `tls/`.
- For production, prefer the KMIP block in `deploy/mongodb/mongod.conf` over a local keyfile.

## 2. Configure the server

`deploy/mongodb/mongod.conf` sets:
- `security.enableEncryption: true`, `encryptionCipherMode: AES256-GCM`
- `net.tls.mode: requireTLS` — plaintext connections are refused
- `net.tls.disabledProtocols: TLS1_0,TLS1_1`
- Optional mutual TLS via `allowConnectionsWithoutCertificates: false` once client certificates are issued

Start: `mongod --config deploy/mongodb/mongod.conf`

> Enabling encryption on an **existing** unencrypted deployment requires `mongodump` → wipe → start encrypted → `mongorestore` (see `scripts/backup/backup.sh`). New deployments are encrypted from first write.

## 3. Update the application connection

`backend/.env`:

```
MONGO_URL=mongodb://aegis_app:****@mongodb.internal:27017/aegis_soc?tls=true&tlsCAFile=/etc/mongodb-tls/ca.pem&tlsCertificateKeyFile=/etc/mongodb-tls/client.pem&retryWrites=true&w=majority
```

Motor passes TLS options through to PyMongo; with `requireTLS` on the server, any misconfigured client fails closed.

## 4. Verify

```bash
mongosh --tls --tlsCAFile=/secure/tls/ca.pem --eval 'db.serverStatus().security'
# expect: encryption enabled; connections rejected without --tls
mongosh "mongodb://localhost:27017" --eval 'db.runCommand({ping:1})'   # MUST fail
```

## 5. Key rotation

Rotate the master key annually (`--rotateMasterKey` with KMIP, or re-key via dump/restore). Log rotations in the audit register.
