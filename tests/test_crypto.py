import pytest
from cryptography.exceptions import InvalidTag, InvalidSignature
from sym import SymKeyStore, encrypt_gcm, decrypt_gcm, encrypt_cbc_hmac, decrypt_cbc_hmac
from asym import gen_rsa, save_priv_pem, save_pub_pem, load_priv, sign, verify
from hybrid import encrypt_hybrid, decrypt_hybrid

def test_sym_gcm_and_tamper(tmp_path):
    ks = SymKeyStore(str(tmp_path / 'ks.json'))
    _, key = ks.new('test', 256)
    src = tmp_path / 'in.txt'; src.write_bytes(b'secret payload')
    enc = tmp_path / 'out.gcm'; dec = tmp_path / 'dec.txt'
    encrypt_gcm(str(src), str(enc), key)
    decrypt_gcm(str(enc), str(dec), key)
    assert dec.read_bytes() == b'secret payload'
    raw = bytearray(enc.read_bytes()); raw[-1] ^= 0xFF; enc.write_bytes(bytes(raw))
    with pytest.raises(InvalidTag):
        decrypt_gcm(str(enc), str(dec), key)

def test_sym_cbc_hmac_and_tamper(tmp_path):
    ks = SymKeyStore(str(tmp_path / 'ks.json'))
    _, key = ks.new('test_cbc', 256)
    src = tmp_path / 'in.txt'; src.write_bytes(b'cbc-hmac payload')
    enc = tmp_path / 'out.cbc'; dec = tmp_path / 'dec.txt'
    encrypt_cbc_hmac(str(src), str(enc), key)
    decrypt_cbc_hmac(str(enc), str(dec), key)
    assert dec.read_bytes() == b'cbc-hmac payload'
    raw = bytearray(enc.read_bytes()); raw[-1] ^= 0xFF; enc.write_bytes(bytes(raw))
    with pytest.raises(InvalidSignature):
        decrypt_cbc_hmac(str(enc), str(dec), key)

def test_rsa_and_hybrid(tmp_path):
    priv, pub = gen_rsa(2048)
    p_path = str(tmp_path / 'priv.pem'); u_path = str(tmp_path / 'pub.pem')
    save_priv_pem(priv, p_path, 'pass123')
    save_pub_pem(pub, u_path)
    with pytest.raises(ValueError):
        load_priv(p_path, 'wrong_pass')
    sig = sign(priv, b'hello')
    assert verify(pub, sig, b'hello') is True
    assert verify(pub, sig, b'tampered') is False

    src = tmp_path / 'h.txt'; src.write_bytes(b'hybrid secret')
    henc = tmp_path / 'h.bin'; hdec = tmp_path / 'h.dec'
    encrypt_hybrid(u_path, str(src), str(henc))
    decrypt_hybrid(p_path, 'pass123', str(henc), str(hdec))
    assert hdec.read_bytes() == b'hybrid secret'
