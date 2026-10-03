# MongoDB hardening

Production Aegis requires MongoDB TLS and WiredTiger encryption at rest.

1. Generate/store the WiredTiger encryption key with a secret manager. Never commit it.
2. Mount the server certificate and CA certificate as secrets.
3. Start mongod with ops/mongodb/mongod.conf.
4. Use a MongoDB URI with TLS and SCRAM-SHA-256 credentials.
5. Set MONGO_TLS_CA_FILE and, when mutual TLS is required, MONGO_TLS_CERT_KEY_FILE.
6. Never enable MONGO_TLS_ALLOW_INVALID_CERTS in production.
7. Test restore and decryption procedures before production rollout.

WiredTiger encryption is a MongoDB server-side feature, so this repository supplies deployment configuration rather than pretending a connection string alone enables at-rest encryption.
