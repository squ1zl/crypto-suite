import os, json, struct, secrets, time
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib

MAGIC = b'CSYM'
VERSION = 1
CHUNK = 1024 * 1024
MAX_KEY_USES = 100
MAX_KEY_AGE_SEC = 30 * 24 * 3600

class SymKeyStore:
    def __init__(self, path='keystore.json'):
        self.path = path
        self.db = {'keys': []}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                self.db = json.load(f)

    def new(self, label: str, bits: int = 256):
        if bits not in (128, 192, 256):
            raise ValueError('Key size must be 128, 192, or 256 bits')
        key = secrets.token_bytes(bits // 8)
        salt = secrets.token_bytes(16)
        key_id = secrets.token_hex(8)
        for k in self.db['keys']:
            if k['label'] == label and k.get('status') == 'active':
                k['status'] = 'rotated'
        meta = {
            'label': label,
            'key_id': key_id,
            'bits': bits,
            'salt': salt.hex(),
            'created_at': int(time.time()),
            'uses': 0,
            'max_uses': MAX_KEY_USES,
            'status': 'active',
        }
        self.db['keys'].append(meta)
        self.save()
        return meta, key

    def record_use(self, label: str):
        now = int(time.time())
        for k in reversed(self.db['keys']):
            if k['label'] == label and k.get('status') == 'active':
                if k['uses'] >= k.get('max_uses', MAX_KEY_USES) or (now - k['created_at']) > MAX_KEY_AGE_SEC:
                    k['status'] = 'expired'
                    self.save()
                    raise RuntimeError(f"Key '{label}' ({k['key_id']}) expired/exhausted. Rotate key via 'sym rotate'.")
                k['uses'] += 1
                self.save()
                return k
        return None

    def list_keys(self):
        return self.db['keys']

    def save(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)


def _derive_cbc_keys(master_key: bytes, salt: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=len(master_key) + 32,
        salt=salt,
        info=b'crypto-suite-aes-cbc-hmac',
    )
    okm = hkdf.derive(master_key)
    return okm[:len(master_key)], okm[len(master_key):]


def _pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',', ':')).encode('utf-8')
    return MAGIC + struct.pack('>H', len(blob)) + blob


def _unpack_header(fp) -> dict:
    magic = fp.read(4)
    if magic != MAGIC:
        raise ValueError('Invalid container format: bad magic bytes')
    raw_len = fp.read(2)
    if len(raw_len) < 2:
        raise ValueError('Invalid container format: truncated header length')
    (hl,) = struct.unpack('>H', raw_len)
    raw_hdr = fp.read(hl)
    if len(raw_hdr) < hl:
        raise ValueError('Invalid container format: truncated header JSON')
    return json.loads(raw_hdr.decode('utf-8'))


def validate_aes_key(key: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError(f'Invalid AES key length: {len(key)*8} bits (expected 128, 192, or 256)')


def encrypt_gcm(in_path: str, out_path: str, key: bytes, aad: Optional[bytes] = None):
    validate_aes_key(key)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    h = {'v': VERSION, 'mode': 'GCM', 'nonce': nonce.hex(), 'alg': f'AES-{len(key)*8}-GCM'}
    header = _pack_header(h)
    with open(in_path, 'rb') as fi:
        data = fi.read()
    ct = aesgcm.encrypt(nonce, data, header if aad is None else aad)
    with open(out_path, 'wb') as fo:
        fo.write(header)
        fo.write(ct)


def decrypt_gcm(in_path: str, out_path: str, key: bytes, aad: Optional[bytes] = None):
    validate_aes_key(key)
    with open(in_path, 'rb') as f:
        hdr = _unpack_header(f)
        if hdr.get('mode') != 'GCM':
            raise ValueError(f"Mode mismatch: expected GCM, got {hdr.get('mode')}")
        data = f.read()
    nonce = bytes.fromhex(hdr['nonce'])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, data, _pack_header(hdr) if aad is None else aad)
    with open(out_path, 'wb') as fo:
        fo.write(pt)


def encrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    validate_aes_key(key)
    iv = secrets.token_bytes(16)
    salt = secrets.token_bytes(16)
    enc_key, mac_key = _derive_cbc_keys(key, salt)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    h = {
        'v': VERSION,
        'mode': 'CBC-HMAC',
        'iv': iv.hex(),
        'salt': salt.hex(),
        'alg': f'AES-{len(enc_key)*8}-CBC',
        'mac': 'HMAC-SHA256',
    }
    header = _pack_header(h)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(header)
    mac.update(iv)
    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        fo.write(iv)
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            c = enc.update(padder.update(chunk))
            if c:
                fo.write(c)
                mac.update(c)
        c = enc.update(padder.finalize()) + enc.finalize()
        if c:
            fo.write(c)
            mac.update(c)
        fo.write(mac.finalize())


def decrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    validate_aes_key(key)
    with open(in_path, 'rb') as f:
        hdr = _unpack_header(f)
        if hdr.get('mode') != 'CBC-HMAC':
            raise ValueError(f"Mode mismatch: expected CBC-HMAC, got {hdr.get('mode')}")
        iv = bytes.fromhex(hdr['iv'])
        salt = bytes.fromhex(hdr['salt'])
        read_iv = f.read(16)
        if read_iv != iv:
            raise ValueError('Corrupted container: IV mismatch')
        body = f.read()
    if len(body) < 32:
        raise ValueError('Corrupted container: missing HMAC tag')
    tag, data = body[-32:], body[:-32]
    enc_key, mac_key = _derive_cbc_keys(key, salt)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(_pack_header(hdr))
    mac.update(iv)
    mac.update(data)
    mac.verify(tag)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    dec = cipher.decryptor()
    unpad = padding.PKCS7(128).unpadder()
    pt = unpad.update(dec.update(data) + dec.finalize()) + unpad.finalize()
    with open(out_path, 'wb') as fo:
        fo.write(pt)
