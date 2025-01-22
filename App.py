import streamlit as st
from PIL import Image
import hashlib

# Function to encode the message with passcode using LSB
def encode_message_lsb_with_passcode(image_path, secret_text, output_path, passcode):
    # Generate a hashed passcode using SHA-256
    hashed_passcode = hashlib.sha256(passcode.encode('utf-8')).hexdigest()
    
    # Append the hashed passcode to the secret text
    secret_text = hashed_passcode + secret_text + "Ending"
    
    # Open the image
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    
    # Convert the secret text to binary (UTF-8 encoding)
    binary_secret_text = ''.join(format(byte, '08b') for byte in secret_text.encode('utf-8'))
    
    # Check if the image can accommodate the secret text
    image_capacity = image.width * image.height * 3
    if len(binary_secret_text) > image_capacity:
        raise ValueError("Image does not have sufficient capacity to hide the secret text.")
    
    # Hide the secret text in the image
    index = 0
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]
            
            # Modify the least significant bit of each color channel
            if index < len(binary_secret_text):
                r = (r & 0xFE) | int(binary_secret_text[index])
                index += 1
            if index < len(binary_secret_text):
                g = (g & 0xFE) | int(binary_secret_text[index])
                index += 1
            if index < len(binary_secret_text):
                b = (b & 0xFE) | int(binary_secret_text[index])
                index += 1
            
            pixels[i, j] = (r, g, b)
            
            if index >= len(binary_secret_text):
                break
        if index >= len(binary_secret_text):
            break
    
    # Save the image with the hidden secret text
    image.save(output_path)
    print("Secret text hidden successfully.")

# Function to decode the message with passcode from LSB
def decode_message_lsb_with_passcode(image_path, passcode):
    # Generate a hashed passcode using SHA-256
    hashed_passcode = hashlib.sha256(passcode.encode('utf-8')).hexdigest()
    
    # Open the image
    image = Image.open(image_path)
    pixels = image.load()
    
    # Extract the secret text from the image
    binary_secret_text = ""
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]
            
            # Extract the least significant bit of each color channel
            binary_secret_text += str(r & 1)
            binary_secret_text += str(g & 1)
            binary_secret_text += str(b & 1)
    
    # Convert the binary text to ASCII
    binary_chunks = [binary_secret_text[i:i+8] for i in range(0, len(binary_secret_text), 8)]
    secret_text = ""
    for chunk in binary_chunks:
        char = chr(int(chunk, 2))
        secret_text += char
        if secret_text.endswith("Ending"):
            break
    
    # Remove the delimiter
    extracted_passcode = secret_text[:64]  # Extract the first 64 characters (hashed passcode)
    if extracted_passcode != hashed_passcode:
        raise ValueError("Incorrect passcode.")
    
    return secret_text[64:].replace("Ending", "")  # Remove the passcode and delimiter 

# Streamlit UI
st.title("Image Steganography with Passcode Security")

# Sidebar to navigate between encoding and decoding
option = st.sidebar.selectbox("Choose an option", ["Encode Message", "Decode Message"])

# Encoding page
if option == "Encode Message":
    st.subheader("Hide a Secret Message in an Image")
    uploaded_image = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg"])

    if uploaded_image:
        image = Image.open(uploaded_image)
        secret_message = st.text_area("Enter the secret message to hide")
        passcode = st.text_input("Enter a passcode")
        
        # Add instructions for passcode
        st.write("**Passcode Requirement:**")
        st.write("1. The passcode can be any string, including special characters, numbers, or letters.")
        st.write("2. It will be hashed using SHA-256 to ensure security.")
        st.write("3. You will need to enter the same passcode to decode the hidden message.")
        
        if st.button("Encode"):
            if secret_message and passcode:
                # Save the uploaded image to a temporary file
                image_path = "temp_image.png"
                image.save(image_path)

                # Define the output path for the encoded image
                output_path = "encoded_image.png"

                # Encode the message with the passcode
                try:
                    encode_message_lsb_with_passcode(image_path, secret_message, output_path, passcode)
                    st.image(output_path, caption="Encoded Image", use_container_width=True)
                    st.download_button("Download Encoded Image", output_path, "encoded_image.png")
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Please provide both the message and passcode.")
    
# Decoding page
if option == "Decode Message":
    st.subheader("Retrieve a Secret Message from an Image")
    uploaded_encoded_image = st.file_uploader("Upload the encoded image", type=["png", "jpg", "jpeg"])

    if uploaded_encoded_image:
        encoded_image = Image.open(uploaded_encoded_image)
        passcode = st.text_input("Enter the passcode to decode the message")

        # Add instructions for passcode
        st.write("**Passcode Requirement:**")
        st.write("1. Enter the same passcode used for encoding the message.")
        st.write("2. The passcode is hashed and embedded into the image for validation.")

        if st.button("Decode"):
            if passcode:
                # Save the uploaded encoded image to a temporary file
                encoded_image_path = "encoded_image.png"
                encoded_image.save(encoded_image_path)

                # Decode the secret message
                try:
                    decoded_message = decode_message_lsb_with_passcode(encoded_image_path, passcode)
                    st.success("Decoded Message: " + decoded_message)
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Please provide the passcode.")
