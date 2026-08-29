import os
import random
import shutil

src_ben = "/home/edo/Desktop/DatasetUnited/benign"
src_mal = "/home/edo/Desktop/DatasetUnited/malware"

dst_ben = "/home/edo/Desktop/FinalDataset/benign"
dst_mal = "/home/edo/Desktop/FinalDataset/malware"

os.makedirs(dst_ben, exist_ok=True)
os.makedirs(dst_mal, exist_ok=True)

ben_files = os.listdir(src_ben)
mal_files = os.listdir(src_mal)

ben_sel = random.sample(ben_files, 2000)
mal_sel = random.sample(mal_files, 2000)

print("completed sample")


for f in ben_sel:
    shutil.copy(os.path.join(src_ben, f), dst_ben)
    
for f in mal_sel:
    shutil.copy(os.path.join(src_mal, f), dst_mal)
    
print("completed transfer")



