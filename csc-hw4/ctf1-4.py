#!/usr/bin/env python

from zipfile import ZipFile
import os
from PIL import Image
import pytesseract

# find ffd9 (trailer) in jpg
def find_trailer(jpg):
    trailer = b'\xff\xd9'
    trailer_len = len(trailer)
    for i in range(len(jpg) - trailer_len):
        if jpg[i:i+trailer_len] == trailer:
            return i
    return -1

if __name__ == '__main__':
    with open('./server-ctf-src/doll/Matryoshka dolls.jpg', 'rb') as f:
        jpg = f.read()
    trailer = find_trailer(jpg)
    zip = jpg[trailer+2:]
    with open('./tmp.zip', 'wb') as f:
        f.write(zip)
    with ZipFile('./tmp.zip', 'r') as f:
        f.extractall('./')
    os.system('rm ./tmp.zip')
    img = Image.open('./flag.txt')
    text = pytesseract.image_to_string(img, lang='eng')
    print(text, end='')
    os.system('rm ./flag.txt')
