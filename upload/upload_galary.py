import requests
from xml.etree import ElementTree as ET
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import MD5
import os
import random
import mimetypes
import time

session = requests.Session()


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

def crypt_encode(plaintext_str: str, pass_key: str) -> str:
    # JSON.stringify()와 동일하게 문자열 처리
    json_encoded_str = json.dumps(plaintext_str)

    # pass_key를 string → bytes로 인코딩 (utf-8)
    passkey_bytes = pass_key.encode("utf-8")

    # salt 8바이트 랜덤 생성
    salt = get_random_bytes(8)

    # OpenSSL KDF 방식으로 key, iv 생성
    key, iv = evp_kdf_md5(passkey_bytes, salt)

    # AES CBC 암호화
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(json_encoded_str.encode("utf-8"), AES.block_size))

    # anyCryptAesJson 포맷 구성
    aes_json = {
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "iv": iv.hex(),
        "s": salt.hex(),
    }

    # JSON → base64 인코딩하여 반환
    return base64.b64encode(json.dumps(aes_json).encode("utf-8")).decode("utf-8")



def login(id : str,pw : str):
    # 1단계: trickKey 요청
    r1 = session.post("http://www.bs1997.13.anyline.kr/core/xml/crypt_khkHjkHjkHbgd.xml.html")
    xml1 = ET.fromstring(r1.text)
    trickKey = xml1.findtext(".//cryptKey")


    # 2단계: trickKey로 다시 요청
    r2 = session.post("http://www.bs1997.13.anyline.kr/core/xml/crypt.xml.html", data={"trickKey": trickKey})
    xml2 = ET.fromstring(r2.text)
    crypt_key1 = xml2.findtext(".//cryptKey")

    # 3단계: cryptKey랑 passKey(tmp)를 얻음
    r3 = session.post("http://www.bs1997.13.anyline.kr/core/anySecure/anySecure.xml.php", data={"action": "getPassKey"})
    xml3 = ET.fromstring(r3.text)
    crypt_key2 = xml3.findtext(".//anySecureCryptKey")
    tmp_key = xml3.findtext(".//anySecurePassKey")

    # 4단계: tmpKey를 passKey로 만듬
    pass_key = str_decode(tmp_key)
    
    # 5단계: id,pw, cryptKey를 암호화시킴
    ids = crypt_encode(id,pass_key)
    pws = crypt_encode(pw,pass_key)
    crypt_keys = crypt_encode(crypt_key1,pass_key)
    
    # 6단계: 로그인하기
    r4 = session.post(
        "http://www.bs1997.13.anyline.kr/core/admin/login/loginCheck.php", 
        data={
            "cryptKey": "",
            "id": "",
            "password": "",
            "ANYSECUREENCODE_cryptKey": crypt_keys,
            "ANYSECUREENCODE_id": ids,
            "ANYSECUREENCODE_password": pws,
            "ANYSECURE_CRYPTKEY": crypt_key2
        }
    )
    print(r4.text)
    
#file upload할 때 필요한 랜덤넘버 만드는 함수
def generate_save_name(idx: int, ext: str) -> str:
    rand_part = str((random.random() * 1000000))
    return f"{rand_part}_{idx}.{ext}"


def writethefile(file_path : str, idx: int): 
    session.cookies.set("ANYBOARD_www23", "Type1")
    filename = os.path.basename(file_path)
    name, ext = os.path.splitext(filename)         #file의 확장자와 이름으로 분리시킴
    ext = ext.lstrip(".").lower()                  # ".jpg" -> "jpg"
    
    save_name = generate_save_name(idx, ext)
    
    mime_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
    
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Origin": "http://admin.bs1997.13.anyline.kr",
        "Referer":"http://admin.bs1997.13.anyline.kr/core/admin/board/board.php?boardID=www23&Mode=write&page=1&keyfield=&key=&bCate="
    })
    
    # 1단계: 파일 첨부(upload.php)
    with open(file_path, "rb") as f:
        files = { 
            "file": (filename, f, mime_type) ,
            "saveName": (None, save_name)
        }
        r1 = session.post("http://www.bs1997.13.anyline.kr/core/uploader/upload.php", files=files)
        #print(r1.request.headers)
        
    # 2단계: 글쓰기 직전에 첨부된 파일들을 서버에 등록(anyboard.xml.html)
    data = {
        "action": "getTempFileInfo",
        "key": str(idx),
        "saveName": save_name,
        "boardID": "www23",
        "Mode": "write"
    }
    r2 = session.post("http://www.bs1997.13.anyline.kr/core/xml/anyboard/anyboard.xml.html", data=data)
    #print(r2.text)
    xml2 = ET.fromstring(r2.text)
    imgLink = xml2.findtext(".//imgLink")
    imgHeight = xml2.findtext(".//imgHeight")
    imgWidth = xml2.findtext(".//imgWidth")
    fileSize = xml2.findtext(".//fileSize")
    #print(imgLink)
    return save_name, fileSize, imgHeight, imgWidth, imgLink

def parse_folder_name(folder_name: str):
    parts = folder_name.split('_', 1)  # 앞에서 2번만 split
    if len(parts) != 2:
        raise ValueError("폴더 이름이 'index_YYYY-MM-DD_subject' 형태여야 합니다.")

    index = parts[0]
    #date = parts[1]
    subject = parts[1]

    # 날짜 further split
    #year, month, day = date.split('-')
    
    return subject
    
def writethetext(folder_path, idx):
    
    r1 = session.post("http://www.bs1997.13.anyline.kr/core/xml/crypt_khkHjkHjkHbgd.xml.html")
    xml1 = ET.fromstring(r1.text)
    trickKey = xml1.findtext(".//cryptKey")


    # 2단계: trickKey로 다시 요청
    r2 = session.post("http://www.bs1997.13.anyline.kr/core/xml/crypt.xml.html", data={"trickKey": trickKey})
    xml2 = ET.fromstring(r2.text)
    ck1 = xml2.findtext(".//cryptKey")

    # 3단계: cryptKey랑 passKey(tmp)를 얻음
    r3 = session.post("http://www.bs1997.13.anyline.kr/core/anySecure/anySecure.xml.php", data={"action": "getPassKey"})
    xml3 = ET.fromstring(r3.text)
    ck2 = xml3.findtext(".//anySecureCryptKey")
    tmp_key = xml3.findtext(".//anySecurePassKey")

    # 4단계: tmpKey를 passKey로 만듬
    pk = str_decode(tmp_key)
    
    
    file =[]
    id_value=""
    orgheight=""
    orgwidth=""
    src=""
    html = f"""<div align="center">&nbsp;</div>
    """
    
    files = os.listdir(folder_path)
    files.sort(key=lambda name: int(name.split('_')[0]))
    
    for idx2, dirname in enumerate(files):
        file_path = os.path.join(folder_path, dirname)
        if os.path.isfile(file_path):
            savename, id_value, orgheight, orgwidth, src = writethefile(file_path, idx2)
            html = html + f"""
            <div align="center">
            <img id="{id_value}" orgheight="{orgheight}" orgwidth="{orgwidth}" src="{src}" style="border: currentColor;" width="100%" />
            </div>
            
            """
            file.append(savename+"/"+os.path.basename(file_path))
    html = html + f"""<p style="text-align:left;">&nbsp;</p>"""
            
    #폴더에서 날짜, 제목을 나누는 함수
    foldername_only = os.path.basename(folder_path)
    subject = parse_folder_name(foldername_only)
            
    
    boardID = crypt_encode("www22", pk) #이 부분 게시판 마다 고쳐야 됨.
    processType = crypt_encode("write", pk)
    cryptKey = crypt_encode(ck1, pk)
    returnPage = crypt_encode("aHR0cDovL2FkbWluLmJzMTk5Ny4xMy5hbnlsaW5lLmtyL2NvcmUvYWRtaW4vYm9hcmQvYm9hcmQucGhw", pk)
    uploadType = crypt_encode("1", pk) #1이면 flash 2이면 html5
    cateEssential = crypt_encode("Y", pk)
            
    fname =""
    for i in range(len(file)):
        if i+1 != len(file):
            fname += file[i]
            fname += "|:|"
        else:
            fname +=file[i]
            
    uploadFiles = crypt_encode(fname, pk)
    #regYear = crypt_encode(year, pk)#year
    #regMonth = crypt_encode(month, pk)#month
    #regDay = crypt_encode(day, pk)#day
    #regRem = crypt_encode("1", pk)
    name = crypt_encode("관리자", pk)
    email = crypt_encode("", pk)
    subject_enc = crypt_encode(subject, pk)
    password = crypt_encode("", pk)
    optEditor = crypt_encode("Y", pk)
    content = crypt_encode(html, pk)#
    #dateChange = crypt_encode("Y", pk)
            
    multipart_data = {
        "boardID": (None, ""),
        "processType": (None, ""),
        "returnPage": (None, ""),
        "cryptKey": (None, ""),
        "uploadType":(None, ""),
        "cateEssential": (None, ""),
        "uploadFiles": (None, ""),
        "name": (None, ""),
        "email": (None, ""),
        "subject": (None, ""),
        "password": (None, ""),
        "optEditor": (None, ""),
        "content": (None, ""),
        "ANYSECUREENCODE_boardID" : (None, boardID),
        "ANYSECUREENCODE_processType": (None, processType),
        "ANYSECUREENCODE_returnPage": (None, returnPage),
        "ANYSECUREENCODE_cryptKey": (None, cryptKey),
        "ANYSECUREENCODE_uploadType": (None, uploadType),
        "ANYSECUREENCODE_cateEssential": (None, cateEssential),
        "ANYSECUREENCODE_uploadFiles": (None, uploadFiles),
        "ANYSECUREENCODE_publicStatus": (None, optEditor),
        "ANYSECUREENCODE_optComment": (None, optEditor),
        #"ANYSECUREENCODE_dateChange": (None, dateChange),
        #"ANYSECUREENCODE_regYear": (None, regYear),
        #"ANYSECUREENCODE_regMonth": (None, regMonth),
        #"ANYSECUREENCODE_regDay": (None, regDay),
        #"ANYSECUREENCODE_regHour": (None, regRem),
        #"ANYSECUREENCODE_regMin": (None, regRem),
        #"ANYSECUREENCODE_regSec": (None, regRem),
        "ANYSECUREENCODE_name": (None, name),
        "ANYSECUREENCODE_email": (None, email),
        "ANYSECUREENCODE_subject": (None, subject_enc),
        "ANYSECUREENCODE_password": (None, password),
        "ANYSECUREENCODE_optEditor": (None, optEditor),
        "ANYSECUREENCODE_content": (None, content),
        "ANYSECURE_CRYPTKEY":(None, ck2)
    }
    
    headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Origin": "http://admin.bs1997.13.anyline.kr",
    "Referer": "http://admin.bs1997.13.anyline.kr/core/admin/board/board.php?boardID=www23&Mode=write&page=1&keyfield=&key=&bCate=",
    "Connection": "keep-alive",
}
    session.cookies.set("ANYSELITE", "N", domain="bs1997.13.anyline.kr")

    r = session.post("http://admin.bs1997.13.anyline.kr/core/anyboard/process.php", files=multipart_data, headers=headers)
    print(r.text)
    
if __name__ == '__main__':
    login("","")    #왼쪽에 id, 오른쪽에 pw를 적으면 됨
    
    #directory 선택(선택된 directory에는 파일만 있어야 됨)
    directory="/home/dong/Desktop/file"
    
    # 폴더 리스트 받아오기
    folder_list = os.listdir(directory)

    # 폴더를 숫자 기준으로 정렬
    folder_list.sort(key=lambda name: int(name.split('_')[0]))

    # 3. 반복
    for idx, foldername in enumerate(folder_list):
        folder_path = os.path.join(directory, foldername)
        if os.path.isdir(folder_path):
            result = writethetext(folder_path, idx)
            
            
        
