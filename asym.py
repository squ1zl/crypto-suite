from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asy_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

def gen_rsa(bits: int = 3072):
    if bits not in (2048, 3072, 4096):
        raise ValueError('RSA key size must be 2048, 3072, or 4096 bits')
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()

def gen_ecc(curve_name: str = 'P-256'):
    curves = {'P-256': ec.SECP256R1(), 'P-384': ec.SECP384R1()}
    if curve_name not in curves:
        raise ValueError('Supported ECC curves: P-256, P-384')
    priv = ec.generate_private_key(curves[curve_name])
    return priv, priv.public_key()

def save_priv_pem(priv, path: str, password: str):
    if not password:
        raise ValueError('Password is required to protect private key PEM')
    enc = serialization.BestAvailableEncryption(password.encode('utf-8'))
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(path, 'wb') as f:
        f.write(pem)

def save_pub_pem(pub, path: str):
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, 'wb') as f:
        f.write(pem)

def load_priv(path: str, password: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password.encode('utf-8'))

def load_pub(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def rsa_encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(priv, ct: bytes) -> bytes:
    return priv.decrypt(
        ct,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def sign(priv, data: bytes) -> bytes:
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        return priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return priv.sign(
        data,
        asy_padding.PSS(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            salt_length=asy_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify(pub, sig: bytes, data: bytes) -> bool:
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(
                sig,
                data,
                asy_padding.PSS(
                    mgf=asy_padding.MGF1(hashes.SHA256()),
                    salt_length=asy_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        return True
    except InvalidSignature:
        return False
