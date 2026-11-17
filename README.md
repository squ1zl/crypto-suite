# Crypto Suite (ПР №3–4)

Комплексне криптографічне рішення на Python (`cryptography`):
- **Симетричне шифрування (`sym.py`):** AES-256-GCM (AEAD) та AES-256-CBC + HMAC-SHA256 (*Encrypt-then-MAC* з деривацією ключів HKDF-SHA256 та ротацією ключів у `keystore.json`).
- **Асиметрична криптографія (`asym.py`):** генерація пар RSA (2048/3072/4096) та ECC (P-256/P-384), збереження приватного ключа у зашифрованому PEM, шифрування RSA-OAEP (SHA-256) та цифровий підпис RSA-PSS / ECDSA.
- **Гібридне шифрування (`hybrid.py`):** одноразовий ключ AES-256-GCM, зашифрований RSA-OAEP.
- **CLI, бенчмарки та журналювання (`cli.py`, `logger.py`):** вимірювання швидкості (MB/s), обробка винятків (`InvalidTag`, `InvalidSignature`) та JSON-лог `logs/crypto.jsonl`.
