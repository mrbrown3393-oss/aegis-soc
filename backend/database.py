"""MongoDB connection for Aegis SOC using the native PyMongo Async API."""
from __future__ import annotations

from pymongo import AsyncMongoClient

from config import settings

mongo_kwargs: dict = {"tls": settings.MONGO_TLS}
if settings.MONGO_TLS:
    mongo_kwargs["tlsAllowInvalidCertificates"] = settings.MONGO_TLS_ALLOW_INVALID_CERTS
if settings.MONGO_TLS_CA_FILE and settings.MONGO_TLS:
    mongo_kwargs["tlsCAFile"] = settings.MONGO_TLS_CA_FILE
if settings.MONGO_TLS_CERT_KEY_FILE and settings.MONGO_TLS:
    mongo_kwargs["tlsCertificateKeyFile"] = settings.MONGO_TLS_CERT_KEY_FILE

client = AsyncMongoClient(settings.MONGO_URL, **mongo_kwargs)
db = client[settings.DB_NAME]
