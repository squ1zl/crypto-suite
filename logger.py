import os, json, logging, time

SENSITIVE_KEYS = {'key', 'password', 'secret', 'priv_key', 'mac_key', 'enc_key'}

def _mask(data: dict) -> dict:
    masked = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_KEYS:
            masked[k] = '***MASKED***'
        elif isinstance(v, dict):
            masked[k] = _mask(v)
        else:
            masked[k] = v
    return masked

def get_logger(path='logs/crypto.jsonl'):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    logger = logging.getLogger('crypto')
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(path, encoding='utf-8')
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                payload = {
                    'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'level': record.levelname,
                    'msg': record.getMessage(),
                }
                if hasattr(record, 'extra') and isinstance(record.extra, dict):
                    payload.update(_mask(record.extra))
                return json.dumps(payload, ensure_ascii=False)
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
    return logger
