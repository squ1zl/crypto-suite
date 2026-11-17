import json, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from asym import rsa_encrypt, rsa_decrypt, load_priv, load_pub

MAGIC = b'CHYB'
VERSION = 1

def encrypt_hybrid(pub_pem_path: str, in_path: str, out_path: str):
    pub = load_pub(pub_pem_path)
    aes_key = secrets.token_bytes(32)
    kct = rsa_encrypt(pub, aes_key)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    header = {'v': VERSION, 'mode': 'HYBRID-GCM', 'alg': 'AES-256-GCM+RSA-OAEP', 'nonce': nonce.hex()}
    aad = json.dumps(header, separators=(',', ':')).encode('utf-8')
    with open(in_path, 'rb') as fi:
        data = fi.read()
    ct = aesgcm.encrypt(nonce, data, aad)
    with open(out_path, 'wb') as fo:
        fo.write(MAGIC + len(aad).to_bytes(2, 'big') + aad)
        fo.write(len(kct).to_bytes(2, 'big') + kct)
        fo.write(ct)

def decrypt_hybrid(priv_pem_path: str, password: str, in_path: str, out_path: str):
    with open(in_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError('Invalid hybrid container: bad magic bytes')
        hl = int.from_bytes(f.read(2), 'big')
        aad = f.read(hl)
        kl = int.from_bytes(f.read(2), 'big')
        kct = f.read(kl)
        body = f.read()
    header = json.loads(aad.decode('utf-8'))
    priv = load_priv(priv_pem_path, password)
    aes_key = rsa_decrypt(priv, kct)
    nonce = bytes.fromhex(header['nonce'])
    pt = AESGCM(aes_key).decrypt(nonce, body, aad)
    with open(out_path, 'wb') as fo:
        fo.write(pt)
