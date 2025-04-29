import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import re

BASE_URL = 'http://www.bs1997.kr'
POST_URL = 'http://www.bs1997.kr/default/mp5/mp5_sub1.php?com_board_basic=read_form&com_board_idx={idx}&sub=01&&com_board_id=11'# 기본 설정
base_url = "http://www.bs1997.kr"
# url_template = (
#     "http://www.bs1997.kr/default/mp5/mp5_sub1.php"
#     "?com_board_basic=read_form&com_board_idx={idx}&sub=01"
#     "&&com_board_search_code=&com_board_search_value1=&com_board_search_value2="
#     "&&com_board_page=&&com_board_id=11&&com_board_id=11"
# )

url_template = (
    "http://www.bs1997.kr/default/mp3/mp3_sub5.php"
    "?com_board_basic=read_form&com_board_idx={idx}&sub=05"
    "&&com_board_search_code=&com_board_search_value1=&com_board_search_value2="
    "&&com_board_page=&&com_board_id=34&&com_board_id=34"
)

# 저장 폴더
main_dir = "/home/dong/Desktop/file/다음세대/영어성경부"
os.makedirs(main_dir, exist_ok=True)

# 크롤링 범위 설정 (예: 370~380)
start_idx = 1
end_idx = 46

headers = {
    "User-Agent": "Mozilla/5.0"
}

exclude_names = {"prev.gif", "next.gif", "write.gif", "list.gif"}
for idx in range(start_idx, end_idx + 1):
    page_url = url_template.format(idx=idx)
    print(f"[{idx}] 요청 중: {page_url}")
    try:
        res = requests.get(page_url, headers=headers, timeout=10)
        res.encoding = 'euc-kr'
        if res.status_code != 200:
            print(f"  → 접근 실패 (status code: {res.status_code})")
            continue
        soup = BeautifulSoup(res.text, "html.parser")
        img_tags = soup.select('#post_area img')
        title_tags = soup.select('td.board_desc')        # 제목 텍스트 추출
        title = ""
        upload_date = ""
        if title_tags:
            title = title_tags[0].get_text(strip=True) if len(title_tags) > 0 else ""
            upload_date = title_tags[2].get_text(strip=True) if len(title_tags) > 2 else ""
            print(title)
        else:
            print("제목을 찾을 수 없습니다.")
            
        folder_name = re.sub(r'[\\/*?:"<>|]', "", upload_date) + "_" + re.sub(r'[\\/*?:"<>|]', "", title) # 파일 시스템에서 사용할 수 없는 문자 제거
        folder_path = os.path.join(main_dir, str(idx) + "_" + folder_name)
        os.makedirs(folder_path, exist_ok=True)
        
        if not img_tags:
            print("  → 이미지 없음")
            continue
        
        for idx_img, img in enumerate(img_tags, start=1):
            src = img.get("src")
            if not src:
                continue
            full_url = urljoin(base_url, src)
            filename = full_url.split("/")[-1]
            if filename in exclude_names:
                print(f"  → 제외된 이미지: {filename}")
                continue
            # img_name = f"{idx}_" + filename
            img_name = str(idx_img) + "_" + filename
            
            img_data = requests.get(full_url).content
            with open(os.path.join(folder_path, img_name), "wb") as f:
                f.write(img_data)
            print(f"  → 다운로드 완료: {img_name}")
    except Exception as e:
        print(f"  → 오류 발생: {e}")