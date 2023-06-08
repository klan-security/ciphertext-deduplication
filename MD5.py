import hashlib

def get_file_md5(filepath):
    m = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            m.update(data)
    return m.hexdigest()

def get_str_md5(content):
    m = hashlib.md5(content)
    return m.hexdigest()

if __name__ == "__main__":
    file_MD5 = get_file_md5('D:\test.pptx')
    print(file_MD5)