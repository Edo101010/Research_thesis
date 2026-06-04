import os
import shutil
import math
import numpy as np
from PIL import Image
import sys
import bisect
import colorama
from tqdm import tqdm

src_ben = "/home/edo/Desktop/FinalDataset/benign"
src_mal = "/home/edo/Desktop/FinalDataset/malware"

dst_ben = "/home/edo/Desktop/DatasetEntropy/benign"
dst_mal = "/home/edo/Desktop/DatasetEntropy/malware"

os.makedirs(dst_ben, exist_ok=True)
os.makedirs(dst_mal, exist_ok=True)

ben_files = os.listdir(src_ben)
mal_files = os.listdir(src_mal)


# 1. Shannon entropy of a block

def shannon_entropy(block):
    if len(block) == 0:
        return 0.0
    counts = np.bincount(block, minlength=256)
    probs = counts / len(block)
    nonzero = probs[probs > 0]
    return -np.sum(nonzero * np.log2(nonzero))



# 2. Compute normalized entropy sequence

def compute_entropy_sequence(data, block_size=256, stride=32):
    N = len(data)
    entropy_values = []

    for i in range(0, N - block_size + 1, stride):
        block = data[i:i + block_size]
        H = shannon_entropy(block)
        entropy_values.append(H / 8.0)

    #print(len(np.array(entropy_values)))
    return np.array(entropy_values)

def build_grayscale_image_simple(entropy_values):
    # map entropy
    pixels = np.array(entropy_values * 255, dtype=np.uint8)

    # determine size of square image
    side = int(np.ceil(np.sqrt(len(pixels))))
    canvas = np.zeros((side, side), dtype=np.uint8)

    # fill canvas row by row
    canvas.flat[:len(pixels)] = pixels

    # return image
    return Image.fromarray(canvas, mode='L')



# Full pipeline

def malware_to_grayscale_entropy_image_simple(file_path, name_file, output_path):
    #print(name_file)
    with open(file_path, "rb") as f:
        byte_data = np.frombuffer(f.read(), dtype=np.uint8)
    #print(len(byte_data))
    entropy_vals = compute_entropy_sequence(byte_data)
    
    img = build_grayscale_image_simple(entropy_vals)
    img.save(os.path.join(output_path, name_file + ".png"))



progressbar = tqdm(total=2000)

for f in ben_files:
    malware_to_grayscale_entropy_image_simple(os.path.join(src_ben, f), f, dst_ben)
    progressbar.update()
print("benign files conversion completed")

progressbar.clear()
progressbar2 = tqdm(total=2000)

for f in mal_files:
    malware_to_grayscale_entropy_image_simple(os.path.join(src_mal, f), f, dst_mal)
    progressbar2.update()
print("malware files conversion completed")
