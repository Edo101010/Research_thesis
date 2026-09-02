The following repository contains the initial testing for my dissertation project.
The project objective is to analyse the impact that different byte-to-image transformations have on the effectiveness of CNN models in classifying malware and detecting it.

The malware and benign executables were converted into image data using four different binary-to-image encoding methods, creating four different datasets. These encoding methods include binary conversion, byteclass conversion, entropy conversion, and hybrid conversion.

The binary conversion, or Grayscale Byte Mapping (Baseline), functions by mapping each byte in the file binary format to a pixel intensity (0–255). This one-dimensional array is then reshaped into a two-dimensional array,  forming a grayscale image. In contrast, Byteclass Mapping converts bytes into integer values according to predefined encoding classes. Each byte is assigned to a class based on its ASCII value and data type, and the corresponding class value is then mapped to a pixel in the image representation. 
The entropy-based conversion, or 2D Entropy Mapping, uses statistical entropy of byte sequences to represent local information complexity in image form, creating texture-rich images. In this study, this is achieved by computing the Shannon entropy formula for blocks of 256 bytes with a stride of 32. This array is then converted into a grayscale image.
The Hybrid Mapping uses the previously mentioned encoding types as components for its representation. RGB images are composed of 3 channels, each representing a colour with an intensity between 0 and 255. The hybrid conversion simply uses the binary, entropy and byteclass mapping as single channels for the final RGB image. 

<img src='https://github.com/Edo101010/Research_thesis/blob/main/ImageRedame/results.PNG' width=80%>
<img src='https://github.com/Edo101010/Research_thesis/blob/main/ImageRedame/4xdataset_sample.PNG' width=60%>
