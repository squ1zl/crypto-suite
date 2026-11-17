import argparse, os, sys, time, base64, secrets
from cryptography.exceptions import InvalidTag, InvalidSignature
from logger import get_logger
from sym import SymKeyStore, encrypt_gcm, decrypt_gcm, encrypt_cbc_hmac, decrypt_cbc_hmac
from asym import gen_rsa, gen_ecc, save_priv_pem, save_pub_pem, load_priv, load_pub, rsa_encrypt, rsa_decrypt, sign, verify
from hybrid import encrypt_hybrid, decrypt_hybrid

logger = get_logger()

def sym_cmd(args):
    ks = SymKeyStore()
    if args.action in ('new', 'rotate'):
        meta, key = ks.new(args.label, bits=args.bits)
        logger.info(f'sym.{args.action}', extra={'extra': meta})
        print(f"[{args.action.upper()}] key_id={meta['key_id']} label={meta['label']} bits={meta['bits']}")
        print('KEY (base64, keep secret):', base64.b64encode(key).decode())
    elif args.action == 'list':
        for k in ks.list_keys():
            print(k)
    elif args.action == 'enc':
        key = base64.b64decode(args.key) if args.key else None
        if not key:
            raise ValueError('Provide --key (base64) from sym new output')
        if args.label:
            ks.record_use(args.label)
        t0 = time.perf_counter()
        if args.mode == 'gcm':
            encrypt_gcm(args.infile, args.outfile, key)
        else:
            encrypt_cbc_hmac(args.infile, args.outfile, key)
        dt = time.perf_counter() - t0
        info = {'mode': args.mode.upper(), 'bits': len(key) * 8, 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}
        logger.info('sym.enc', extra={'extra': info})
        print(f"Encrypted ({info['mode']}, {info['bits']}-bit) in {dt:.4f}s -> {args.outfile}")
    elif args.action == 'dec':
        key = base64.b64decode(args.key)
        t0 = time.perf_counter()
        if args.mode == 'gcm':
            decrypt_gcm(args.infile, args.outfile, key)
        else:
            decrypt_cbc_hmac(args.infile, args.outfile, key)
        dt = time.perf_counter() - t0
        info = {'mode': args.mode.upper(), 'bits': len(key) * 8, 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}
        logger.info('sym.dec', extra={'extra': info})
        print(f"Decrypted ({info['mode']}, {info['bits']}-bit) in {dt:.4f}s -> {args.outfile}")


def rsa_cmd(args):
    if args.action == 'gen':
        t0 = time.perf_counter()
        priv, pub = gen_rsa(args.bits)
        os.makedirs(os.path.dirname(args.priv) or '.', exist_ok=True)
        os.makedirs(os.path.dirname(args.pub) or '.', exist_ok=True)
        save_priv_pem(priv, args.priv, args.password)
        save_pub_pem(pub, args.pub)
        dt = time.perf_counter() - t0
        logger.info('rsa.gen', extra={'extra': {'bits': args.bits, 'priv': args.priv, 'pub': args.pub, 'sec': round(dt, 4)}})
        print(f'RSA-{args.bits} keys saved in {dt:.4f}s.')
    elif args.action == 'enc':
        t0 = time.perf_counter()
        pub = load_pub(args.pub)
        with open(args.infile, 'rb') as f:
            ct = rsa_encrypt(pub, f.read())
        with open(args.outfile, 'wb') as f:
            f.write(ct)
        dt = time.perf_counter() - t0
        logger.info('rsa.enc', extra={'extra': {'bits': pub.key_size, 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}})
        print(f'RSA-OAEP ({pub.key_size}-bit) encrypt OK in {dt:.4f}s')
    elif args.action == 'dec':
        t0 = time.perf_counter()
        priv = load_priv(args.priv, args.password)
        with open(args.infile, 'rb') as f:
            pt = rsa_decrypt(priv, f.read())
        with open(args.outfile, 'wb') as f:
            f.write(pt)
        dt = time.perf_counter() - t0
        logger.info('rsa.dec', extra={'extra': {'bits': priv.key_size, 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}})
        print(f'RSA-OAEP ({priv.key_size}-bit) decrypt OK in {dt:.4f}s')
    elif args.action == 'sign':
        t0 = time.perf_counter()
        priv = load_priv(args.priv, args.password)
        with open(args.infile, 'rb') as f:
            sig = sign(priv, f.read())
        with open(args.sig, 'wb') as f:
            f.write(sig)
        dt = time.perf_counter() - t0
        logger.info('rsa.sign', extra={'extra': {'bits': priv.key_size, 'in': args.infile, 'sig': args.sig, 'sec': round(dt, 4)}})
        print(f'Signed ({priv.key_size}-bit) in {dt:.4f}s -> {args.sig}')
    elif args.action == 'verify':
        t0 = time.perf_counter()
        pub = load_pub(args.pub)
        with open(args.sig, 'rb') as fs, open(args.infile, 'rb') as fi:
            ok = verify(pub, fs.read(), fi.read())
        dt = time.perf_counter() - t0
        logger.info('rsa.verify', extra={'extra': {'bits': pub.key_size, 'in': args.infile, 'ok': ok, 'sec': round(dt, 4)}})
        print('VERIFY:', 'OK' if ok else 'FAIL')
        if not ok:
            sys.exit(2)


def ecc_cmd(args):
    if args.action == 'gen':
        t0 = time.perf_counter()
        priv, pub = gen_ecc(args.curve)
        os.makedirs(os.path.dirname(args.priv) or '.', exist_ok=True)
        save_priv_pem(priv, args.priv, args.password)
        save_pub_pem(pub, args.pub)
        dt = time.perf_counter() - t0
        logger.info('ecc.gen', extra={'extra': {'curve': args.curve, 'sec': round(dt, 4)}})
        print(f'ECC-{args.curve} keys saved in {dt:.4f}s.')
    elif args.action == 'sign':
        priv = load_priv(args.priv, args.password)
        with open(args.infile, 'rb') as f:
            sig = sign(priv, f.read())
        with open(args.sig, 'wb') as f:
            f.write(sig)
        logger.info('ecc.sign', extra={'extra': {'curve': priv.curve.name, 'in': args.infile}})
        print(f'ECDSA signed -> {args.sig}')
    elif args.action == 'verify':
        pub = load_pub(args.pub)
        with open(args.sig, 'rb') as fs, open(args.infile, 'rb') as fi:
            ok = verify(pub, fs.read(), fi.read())
        logger.info('ecc.verify', extra={'extra': {'curve': pub.curve.name, 'ok': ok}})
        print('ECDSA VERIFY:', 'OK' if ok else 'FAIL')
        if not ok:
            sys.exit(2)


def hybrid_cmd(args):
    if args.action == 'enc':
        t0 = time.perf_counter()
        encrypt_hybrid(args.pub, args.infile, args.outfile)
        dt = time.perf_counter() - t0
        logger.info('hybrid.enc', extra={'extra': {'alg': 'AES-256-GCM+RSA-OAEP', 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}})
        print(f'Hybrid encrypt (AES-256-GCM + RSA-OAEP) OK in {dt:.4f}s -> {args.outfile}')
    else:
        t0 = time.perf_counter()
        decrypt_hybrid(args.priv, args.password, args.infile, args.outfile)
        dt = time.perf_counter() - t0
        logger.info('hybrid.dec', extra={'extra': {'alg': 'AES-256-GCM+RSA-OAEP', 'in': args.infile, 'out': args.outfile, 'sec': round(dt, 4)}})
        print(f'Hybrid decrypt (AES-256-GCM + RSA-OAEP) OK in {dt:.4f}s -> {args.outfile}')


def bench_cmd(args):
    sizes = []
    for s in args.sizes:
        if s.lower().endswith('mb'):
            sizes.append(int(float(s[:-2]) * 1024 * 1024))
        elif s.lower().endswith('kb'):
            sizes.append(int(float(s[:-2]) * 1024))
        else:
            sizes.append(int(s))
    os.makedirs('outputs', exist_ok=True)
    key = secrets.token_bytes(32)
    results = []
    for size in sizes:
        path = f'outputs/bench_{size}.bin'
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(secrets.token_bytes(size))
        for mode in args.modes:
            t0 = time.perf_counter()
            if mode == 'gcm':
                encrypt_gcm(path, path + '.enc', key)
            else:
                encrypt_cbc_hmac(path, path + '.enc', key)
            e = time.perf_counter() - t0
            t1 = time.perf_counter()
            if mode == 'gcm':
                decrypt_gcm(path + '.enc', path + '.dec', key)
            else:
                decrypt_cbc_hmac(path + '.enc', path + '.dec', key)
            d = time.perf_counter() - t1
            results.append((size, f'AES-256-{mode.upper()}', e, d))

    sample = b'benchmark payload 64 bytes for asymmetric sign/encrypt tests!!'
    for bits in args.rsa_bits:
        t0 = time.perf_counter()
        priv, pub = gen_rsa(bits)
        tg = time.perf_counter() - t0
        t1 = time.perf_counter()
        ct = rsa_encrypt(pub, sample)
        te = time.perf_counter() - t1
        t2 = time.perf_counter()
        rsa_decrypt(priv, ct)
        td = time.perf_counter() - t2
        results.append((0, f'RSA-{bits} (keygen)', tg, 0))
        results.append((0, f'RSA-{bits}-OAEP (enc/dec)', te, td))

    for curve in ('P-256', 'P-384'):
        t0 = time.perf_counter()
        priv, pub = gen_ecc(curve)
        tg = time.perf_counter() - t0
        t1 = time.perf_counter()
        sig = sign(priv, sample)
        ts = time.perf_counter() - t1
        t2 = time.perf_counter()
        verify(pub, sig, sample)
        tv = time.perf_counter() - t2
        results.append((0, f'ECC-{curve} (keygen)', tg, 0))
        results.append((0, f'ECC-{curve}-ECDSA (sign/ver)', ts, tv))

    lines = [
        "| Size (MB) | Algorithm / Mode | Enc / Sign (s) | Dec / Verify (s) | Enc MB/s | Dec MB/s |",
        "|---:|---|---:|---:|---:|---:|",
    ]
    for size, mode, e, d in results:
        mb = size / 1024 / 1024 if size else 0
        enc_mb = f"{mb/e:.1f}" if (size and e > 0) else "-"
        dec_mb = f"{mb/d:.1f}" if (size and d > 0) else "-"
        lines.append(f"| {mb:.1f} | {mode} | {e:.4f} | {d:.4f} | {enc_mb} | {dec_mb} |")
    md_out = "\n".join(lines)
    with open('outputs/bench.md', 'w', encoding='utf-8') as f:
        f.write(md_out)
    logger.info('bench.done', extra={'extra': {'sizes': args.sizes, 'modes': args.modes}})
    print(md_out)
    print('\nSaved -> outputs/bench.md')


def main():
    p = argparse.ArgumentParser(description='Crypto Suite CLI (AES-GCM/CBC-HMAC, RSA-OAEP/PSS, ECC, Hybrid)')
    sp = p.add_subparsers(dest='cmd', required=True)

    ps = sp.add_parser('sym')
    ssp = ps.add_subparsers(dest='action', required=True)
    ps_new = ssp.add_parser('new'); ps_new.add_argument('--label', required=True); ps_new.add_argument('--bits', type=int, default=256)
    ps_rot = ssp.add_parser('rotate'); ps_rot.add_argument('--label', required=True); ps_rot.add_argument('--bits', type=int, default=256)
    ssp.add_parser('list')
    ps_enc = ssp.add_parser('enc'); ps_enc.add_argument('--label'); ps_enc.add_argument('--key'); ps_enc.add_argument('--in', dest='infile', required=True); ps_enc.add_argument('--out', dest='outfile', required=True); ps_enc.add_argument('--mode', choices=['gcm', 'cbc'], required=True)
    ps_dec = ssp.add_parser('dec'); ps_dec.add_argument('--key', required=True); ps_dec.add_argument('--in', dest='infile', required=True); ps_dec.add_argument('--out', dest='outfile', required=True); ps_dec.add_argument('--mode', choices=['gcm', 'cbc'], required=True)

    pr = sp.add_parser('rsa')
    rsp = pr.add_subparsers(dest='action', required=True)
    pr_gen = rsp.add_parser('gen'); pr_gen.add_argument('--bits', type=int, default=3072); pr_gen.add_argument('--priv', required=True); pr_gen.add_argument('--pub', required=True); pr_gen.add_argument('--password', required=True)
    pr_enc = rsp.add_parser('enc'); pr_enc.add_argument('--pub', required=True); pr_enc.add_argument('--in', dest='infile', required=True); pr_enc.add_argument('--out', dest='outfile', required=True)
    pr_dec = rsp.add_parser('dec'); pr_dec.add_argument('--priv', required=True); pr_dec.add_argument('--password', required=True); pr_dec.add_argument('--in', dest='infile', required=True); pr_dec.add_argument('--out', dest='outfile', required=True)
    pr_sig = rsp.add_parser('sign'); pr_sig.add_argument('--priv', required=True); pr_sig.add_argument('--password', required=True); pr_sig.add_argument('--in', dest='infile', required=True); pr_sig.add_argument('--sig', required=True)
    pr_ver = rsp.add_parser('verify'); pr_ver.add_argument('--pub', required=True); pr_ver.add_argument('--in', dest='infile', required=True); pr_ver.add_argument('--sig', required=True)

    pe = sp.add_parser('ecc')
    esp = pe.add_subparsers(dest='action', required=True)
    pe_gen = esp.add_parser('gen'); pe_gen.add_argument('--curve', choices=['P-256', 'P-384'], default='P-256'); pe_gen.add_argument('--priv', required=True); pe_gen.add_argument('--pub', required=True); pe_gen.add_argument('--password', required=True)
    pe_sig = esp.add_parser('sign'); pe_sig.add_argument('--priv', required=True); pe_sig.add_argument('--password', required=True); pe_sig.add_argument('--in', dest='infile', required=True); pe_sig.add_argument('--sig', required=True)
    pe_ver = esp.add_parser('verify'); pe_ver.add_argument('--pub', required=True); pe_ver.add_argument('--in', dest='infile', required=True); pe_ver.add_argument('--sig', required=True)

    ph = sp.add_parser('hybrid')
    hsp = ph.add_subparsers(dest='action', required=True)
    ph_enc = hsp.add_parser('enc'); ph_enc.add_argument('--pub', required=True); ph_enc.add_argument('--in', dest='infile', required=True); ph_enc.add_argument('--out', dest='outfile', required=True)
    ph_dec = hsp.add_parser('dec'); ph_dec.add_argument('--priv', required=True); ph_dec.add_argument('--password', required=True); ph_dec.add_argument('--in', dest='infile', required=True); ph_dec.add_argument('--out', dest='outfile', required=True)

    pb = sp.add_parser('bench')
    pb.add_argument('--sizes', nargs='+', required=True)
    pb.add_argument('--modes', nargs='+', choices=['gcm', 'cbc'], default=['gcm', 'cbc'])
    pb.add_argument('--rsa-bits', nargs='+', type=int, default=[2048, 3072, 4096])

    args = p.parse_args()
    try:
        if args.cmd == 'sym':
            sym_cmd(args)
        elif args.cmd == 'rsa':
            rsa_cmd(args)
        elif args.cmd == 'ecc':
            ecc_cmd(args)
        elif args.cmd == 'hybrid':
            hybrid_cmd(args)
        elif args.cmd == 'bench':
            bench_cmd(args)
    except (InvalidTag, InvalidSignature) as e:
        logger.error('crypto.integrity_fail', extra={'extra': {'cmd': args.cmd, 'error': type(e).__name__}})
        print(f'[SECURITY ERROR] Integrity/Authentication check failed ({type(e).__name__})!', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error('crypto.error', extra={'extra': {'cmd': args.cmd, 'error': str(e)}})
        print(f'[ERROR] {e}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
