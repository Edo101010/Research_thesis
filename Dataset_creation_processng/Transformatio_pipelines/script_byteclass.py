import os
import shutil
import math
import numpy as np
from PIL import Image
import sys
import bisect
import colorama
from tqdm import tqdm
import time

limits = [10, 30, 60, 100, 200, 500, 1000]
widths = [32, 64, 128, 256, 384, 512, 768, 1024]

src_ben = "/home/edo/Desktop/FinalDataset/benign"
src_mal = "/home/edo/Desktop/FinalDataset/malware"

dst_ben = "/home/edo/Desktop/DatasetByteClass/benign"
dst_mal = "/home/edo/Desktop/DatasetByteClass/malware"

os.makedirs(dst_ben, exist_ok=True)
os.makedirs(dst_mal, exist_ok=True)

ben_files = os.listdir(src_ben)
mal_files = os.listdir(src_mal)

def choose_width(f_size_kb):
    idx = bisect.bisect_left(limits, f_size_kb)
    return widths[idx]
    
    
def encode_byteclass(arr):
    """
    Convert a NumPy array of bytes (0–255) into encoded values:
      0 → 0
      1–31, 127 → 255
      32–126, 128–254 → 32
      255 → 128
    """
    out = np.zeros_like(arr, dtype=np.uint8)

    # ASCII control (1–31, 127)
    mask_ctrl = ((arr >= 1) & (arr <= 31)) | (arr == 127)
    out[mask_ctrl] = 255

    # Printable ASCII (32–126, 128–254)
    mask_print = ((arr >= 32) & (arr <= 126)) | ((arr >= 128) & (arr <= 254))
    out[mask_print] = 32

    # Extended ASCII (255)
    out[arr == 255] = 128

    return out


def dynamic_width_binary_to_image(binary_path, name_file, output_path):

    f_size_kb = os.path.getsize(binary_path) / 1024.0
    width = choose_width(f_size_kb)
    
    with open(binary_path, 'rb') as f:
        data = np.frombuffer(f.read(), dtype=np.uint8)
        
    data = encode_byteclass(data)
    # Select height
    height = int(np.ceil(len(data) / width))

    padded_length = width * height
    padded_data = np.pad(data, (0, padded_length - len(data)), 'constant')

    img_array = padded_data.reshape((height, width))

    img = Image.fromarray(img_array.astype(np.uint8), 'L')
    img.save(os.path.join(output_path, name_file + ".png"))
    
progressbar = tqdm(total=2000)

for f in ben_files:
    dynamic_width_binary_to_image(os.path.join(src_ben, f), f, dst_ben)
    progressbar.update()
progressbar.close()
tqdm.write("Benign files conversion completed")

progressbar2 = tqdm(total=2000)

for f in mal_files:
    dynamic_width_binary_to_image(os.path.join(src_mal, f), f, dst_mal)
    progressbar2.update()
progressbar2.close()
tqdm.write("Malware files conversion completed")
