import requests
from xml.etree import ElementTree as ET
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def base64_decode_custom(js_encoded_str: str) -> str:
    # JavaScript와 동일하게 특수문자 제거
    key_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    cleaned = ''.join([c for c in js_encoded_str if c in key_str])

    # padding 처리
    padding = '=' * ((4 - len(cleaned) % 4) % 4)
    cleaned += padding

    # base64 decode (bytes)
    try:
        raw_bytes = base64.b64decode(cleaned)
    except Exception as e:
        raise ValueError("Base64 decode 실패") from e

    # JS의 문자열 처리를 Python에서 수동으로 재현
    decoded = ''
    i = 0
    while i < len(raw_bytes):
        c = raw_bytes[i]
        if c < 128:
            decoded += chr(c)
            i += 1
        elif (c > 191) and (c < 224):
            c2 = raw_bytes[i + 1]
            decoded += chr(((c & 31) << 6) | (c2 & 63))
            i += 2
        else:
            c2 = raw_bytes[i + 1]
            c3 = raw_bytes[i + 2]
            decoded += chr(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63))
            i += 3

    return decoded

def str_decode(encoded: str) -> str:
    s = base64_decode_custom(encoded)
    merged = s[4:6] + s[:4] + s[6:10] + s[10:]
    for _ in range(4):
        merged = base64_decode_custom(merged)
    return merged

def evp_kdf_md5(passkey: bytes, salt: bytes, key_len=32, iv_len=16) -> tuple:
    """CryptoJS OpenSSL 호환 KDF 방식 (MD5 반복)"""
    total_len = key_len + iv_len
    data = b""
    prev = b""
    while len(data) < total_len:
        md5 = MD5.new()
        md5.update(prev + passkey + salt)
        prev = md5.digest()
        data += prev
    return data[:key_len], data[key_len:]

def crypt_decode(encoded_str: str, pass_key: str) -> str:
    # Step 1: base64 디코딩
    decoded_json = base64.b64decode(encoded_str)
    
    # Step 2: JSON 파싱
    aes_json = json.loads(decoded_json)

    ct_b64 = aes_json['ct']  # 암호문 (base64)
    iv_hex = aes_json['iv']  # IV (hex)
    salt_hex = aes_json['s'] # salt (hex)

    # Step 3: 값 변환
    ciphertext = base64.b64decode(ct_b64)
    iv = bytes.fromhex(iv_hex)
    salt = bytes.fromhex(salt_hex)

    # Step 4: pass_key (string) → bytes
    passkey_bytes = pass_key.encode('utf-8')

    # Step 5: evp_kdf_md5로 key, iv 생성
    key, _ = evp_kdf_md5(passkey_bytes, salt)  # 여기서 생성하는 iv는 버린다
    # 위에서 JSON으로 받은 iv를 직접 사용해야 한다 (암호화 당시 IV)

    # Step 6: AES CBC 복호화
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    # Step 7: 패딩 제거
    json_encoded_str = unpad(padded_plaintext, AES.block_size).decode('utf-8')

    # Step 8: json.loads로 원본 복원
    original_str = json.loads(json_encoded_str)
    
    return original_str

crypt_key = 'SXdlRlZqSXhVbkpPVkZwaFUwVndWRlJXV2tabFJscHpWbXRhYkdGNlVqWlhXSEJEVmxkV2MxSnFWbFpYU0VKUVZXeGFWbVZWTVZWUmF6VlRaV3hhTkZkVVFtRlNiVkY0Vkd0c1dGWkVRVGs9'  # (크립트키)

pass_key = str_decode(crypt_key)

# 사용 예시
encoded_content = 'eyJjdCI6InZPaGtnRmd6Q1pyUVZMaG1JTVZVY2c9PSIsIml2IjoiZWE3NzczYjcxYWNlOGVlNWFiOWFiNDkwZjdlZjM3NmUiLCJzIjoiNmEwNTUwOTA1MWFiZjNkMyJ9'  # (ANYSECUREENCODE_content 같은 거)

plaintext = crypt_decode(encoded_content, pass_key)
print(plaintext)
