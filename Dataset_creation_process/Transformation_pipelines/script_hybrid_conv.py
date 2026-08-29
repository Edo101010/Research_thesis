import os
import shutil
import math
import numpy as np
from PIL import Image
import sys
import bisect
import colorama
from tqdm import tqdm

limits = [10, 30, 60, 100, 200, 500, 1000]
widths = [32, 64, 128, 256, 384, 512, 768, 1024]

src_ben = "/home/edo/Desktop/FinalDataset/benign"
src_mal = "/home/edo/Desktop/FinalDataset/malware"

dst_ben = "/home/edo/Desktop/DatasetHybrid/benign"
dst_mal = "/home/edo/Desktop/DatasetHybrid/malware"

os.makedirs(dst_ben, exist_ok=True)
os.makedirs(dst_mal, exist_ok=True)

ben_files = os.listdir(src_ben)
mal_files = os.listdir(src_mal)

#Hybrid
def shannon_entropy(block):
    if len(block) == 0:
        return 0.0
    counts = np.bincount(block, minlength=256)
    probs = counts / len(block)
    nonzero = probs[probs > 0]
    return -np.sum(nonzero * np.log2(nonzero))
    
#2. Compute normalized entropy sequence

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

#Byte

def choose_width(f_size_kb):
    idx = bisect.bisect_left(limits, f_size_kb)
    return widths[idx]


def dynamic_width_binary_to_image(data, f_size_kb):

    width = choose_width(f_size_kb)

    height = int(np.ceil(len(data) / width))

    padded_length = width * height
    padded_data = np.pad(data, (0, padded_length - len(data)), 'constant')

    img_array = padded_data.reshape((height, width))
    
    img = Image.fromarray(img_array.astype(np.uint8), 'L')
    return img
#ByteClass

def encode_byteclass(arr):
    """
    Convert a NumPy array of bytes (0–255) into encoded values
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


def dynamic_byteclass_to_image(data, f_size_kb):

    width = choose_width(f_size_kb)

    data = encode_byteclass(data)
    # Select height
    height = int(np.ceil(len(data) / width))

    padded_length = width * height
    padded_data = np.pad(data, (0, padded_length - len(data)), 'constant')

    img_array = padded_data.reshape((height, width))
    img = Image.fromarray(img_array.astype(np.uint8), 'L')
    
    return img


# Full pipeline

def hybrid_image_simple(file_path, name_file, output_path):
    dimensions = (224,224)
    f_size_kb = os.path.getsize(file_path) / 1024.0
    
    with open(file_path, "rb") as f:
        byte_data = np.frombuffer(f.read(), dtype=np.uint8)
    #print(len(byte_data))
    
    entropy_vals = compute_entropy_sequence(byte_data)
    img_entropy = build_grayscale_image_simple(entropy_vals)
    img_entropy_res = img_entropy.resize(dimensions)
    #img_entropy.show()
    #img_entropy_res.show()
    
    img_byte = dynamic_width_binary_to_image(byte_data, f_size_kb)
    img_byte_res = img_byte.resize(dimensions)
    #img_byte.show()
    #img_byte_res.show()
    
    img_byteclass = dynamic_byteclass_to_image(byte_data, f_size_kb)
    img_byteclass_res = img_byteclass.resize(dimensions, Image.NEAREST)
    #img_byteclass.show()
    #img_byteclass_res.show()
    #print(np.array(img_byteclass))
    
    #print(img_entropy_res.size, img_byte_res.size, img_byteclass_res.size)
    
    stacked_array = np.stack([np.array(img_byte_res),np.array(img_byteclass_res),np.array(img_entropy_res)], axis=2)
    #print(stacked_array.shape)
    
    img_rgb = Image.fromarray(stacked_array, mode='RGB')
    img_rgb.save(os.path.join(output_path, name_file + ".png"))



progressbar = tqdm(total=2000)

for f in ben_files:
    hybrid_image_simple(os.path.join(src_ben, f), f, dst_ben)
    progressbar.update()
progressbar.close()
tqdm.write("Benign files conversion completed")

progressbar2 = tqdm(total=2000)

for f in mal_files:
    hybrid_image_simple(os.path.join(src_mal, f), f, dst_mal)
    progressbar2.update()
progressbar2.close()
tqdm.write("Malware files conversion completed")
