# Image Steganography with Passcode Security

This project implements **LSB Steganography** to hide and retrieve secret messages in images with an additional layer of security using a passcode hashed with **SHA-256**. The system ensures that only someone with the correct passcode can access the hidden message.

## Features

- Hide secret messages in images without noticeable changes.
- Secure the message using SHA-256 passcode hashing.
- Decode and validate messages only with the correct passcode.
- Simple and efficient encoding/decoding process.

## How It Works

### Encoding Process
1. Hash the passcode using **SHA-256**.
2. Combine the hashed passcode with the secret message.
3. Convert the combined message into binary.
4. Embed the binary data into the Least Significant Bits (LSBs) of the image pixels.

### Decoding Process
1. Extract binary data from the LSBs of the image pixels.
2. Reconstruct the binary data into text.
3. Validate the hashed passcode to ensure security.
4. Retrieve the original secret message.

---

## Getting Started

Follow these instructions to set up and run the project locally.

### Prerequisites

- Python 3.7 or higher
- `pip` (Python package manager)
- A compatible image file (e.g., `.png`)

### Setup

1. **Clone the Repository**  
   ```bash
   git clone [https://github.com/your-username/image-steganography.git](https://github.com/fahadrafiq94/Computation_Creativity.git)
2. **Create a Virtual Environment** 
It's recommended to use a virtual environment to manage dependencies.
   ```bash
   python -m venv venv

4. ** Activate the Virtual Environment** 

for Windows:
         ```bash
         venv\Scripts\activate


for Mac os:
         ```bash
         source venv/bin/activate


4. **Install Dependencies** 
Install the required packages from requirements.txt by running the following command:
      ```bash
      pip install -r requirement.txt
