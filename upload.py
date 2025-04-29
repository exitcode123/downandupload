import os
import shutil
import re

# 삭제할 대상 디렉토리
base_directory = "/home/dong/Desktop/file/다음세대/유치부"

# 폴더 목록 가져오기
for foldername in os.listdir(base_directory):
    folder_path = os.path.join(base_directory, foldername)

    # 폴더인지 확인 + 폴더 이름이 '숫자_' 만 있는지 체크
    if os.path.isdir(folder_path) and re.fullmatch(r'\d+__', foldername):
        print(f"Deleting folder: {folder_path}")
        shutil.rmtree(folder_path)