import os

def remove_empty_dirs(path):
    for name in os.listdir(path):
        full_path = os.path.join(path, name)
        if os.path.isdir(full_path) and not os.listdir(full_path):
            print(f"Removing empty directory: {full_path}")
            os.rmdir(full_path)
            

remove_empty_dirs("/home/dong/Desktop/file/다음세대/영어성경부")
