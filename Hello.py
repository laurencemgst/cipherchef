import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zipfile
import io
from io import BytesIO
import os.path

#Layout
# Set page configuration
st.set_page_config(
    page_title="CIPHERCHEF",
    page_icon="🔒",
    layout="centered"
)

hide_menu_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
"""
st.markdown(hide_menu_style, unsafe_allow_html=True)

#Data Pull and Functions
st.markdown("""
<style>
.big-font {
    font-size:80px !important;
}
</style>
""", unsafe_allow_html=True)


#Options Menu
with st.sidebar:
    st.markdown(
        """
        <style>
        .custom-h4 {
            text-align: center;
            color: white;
            font-size: 36px;
            font-family: 'Arial', sans-serif; /* Change the font family as per your preference */
            text-shadow: 2px 2px 4px #000000; /* Add a shadow effect */
            /* Add any other CSS properties to customize the heading */
        }
        .rounded-image {
            border-radius: 15%; /* Makes the corners rounded */
            overflow: hidden; /* Ensures the image stays within the rounded corners */
        }
        </style>
        <center>
        <div class="rounded-image">
            <img src="https://github.com/laurencemgst/cipherchef/blob/main/chipherchef.png?raw=true" alt="Image" width="250">
        </div>
        <h4 class="custom-h4"> Developed by: </h4>
        <p> Laurence O. Magistrado <br> Andrea Krystel Estadilla <br> John Louie Abenir </p>
        </center>
        """,
        unsafe_allow_html=True
    )
    selected = st.selectbox("Select Cryptography Tools", ["Home", "XOR Cipher", "Ceasar Cipher", "Text Hashing","XOR Block Cipher", "File EncryptDecrypt", "RSA"])

#Home Page
if selected=="Home":
    # CSS styles
    def local_css(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    # Apply local CSS
    local_css("styles.css")  # Create a file named styles.css and place your CSS code there

    if __name__ == "__main__":
        st.markdown("<marquee> WELCOME TO CIPHERCHEF | APPLIED CRYPTOGRAPHY WEBSITE </marquee>", unsafe_allow_html=True)
        # Header with custom styling
        st.markdown(
            """
            <h1 style='text-align: center; color: #2a9d8f; font-size: 36px;'>Welcome to CIPHERCHEF!</h1>
            """,
            unsafe_allow_html=True
        )

        # Description with custom styling
        st.markdown(
            """
            <h2 style='text-align: center; color: #32bcab; font-size: 24px;'>APPLIED CRYPTOGRAPHY</h2>
            <p style='text-align: justify; color: #2a9d8f; font-size: 18px;'>Cryptography uses mathematical functions to transform data and prevent it from being read or tampered with by unauthorized parties. Nearly every computing and communications device uses cryptographic technologies to protect the confidentiality and integrity of information that is communicated or stored.</p>
            """,
            unsafe_allow_html=True
        )
        st.markdown("<p style='text-align: center; font-size: 18px;'>👈 <strong>PROTECT YOUR DATA?</strong> You can use any tools available in the sidebar!</p>", unsafe_allow_html=True)

        st.markdown("""
            <center>
            <table>
                <tr>
                    <th> Developed By: </th>
                    <th> Laurence O. Magistrado </th>
                    <th> Andrea Krystel Estadilla </th>
                    <th> John Louie Abenir </th>
                </tr>
            </table>
            </center>
            """, unsafe_allow_html=True)

#XOR Cipher Page
if selected=="XOR Cipher":
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 43%;
        padding-right: 33%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    # Define the CSS style for the button
    button_style = """
    <style>
        .container {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .encrypt-btn {
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 12px;
        }

        .message {
            text-align: center;
            margin-top: 10px;
        }
    </style>
    """

    def xor_encrypt(plaintext, key):
        """Encrypts plaintext using XOR cipher with the given key, displaying bits involved."""
        if len(key) == 0:
            st.write("<div class='container message'>Key length should be greater than zero</div>", unsafe_allow_html=True)
            return b''  # Return an empty byte string if key length is zero

        ciphertext = bytearray()
        for i in range(len(plaintext)):
            plaintext_byte = plaintext[i]
            key_byte = key[i % len(key)]
            cipher_byte = plaintext_byte ^ key_byte
            
            st.write(f"Plaintext byte: {plaintext_byte:08b} = {chr(plaintext_byte)}")
            st.write(f"Key byte:       {key_byte:08b} = {chr(key_byte)}")
            st.write(f"XOR result:     {cipher_byte:08b} = {chr(cipher_byte)}")
            st.write("--------------------")
            ciphertext.append(cipher_byte)
            
        return ciphertext

    def xor_decrypt(ciphertext, key):
        """Decrypts ciphertext using XOR cipher with the given key."""
        return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption


    # Example usage:
    st.markdown(
        """
        <h1 style='text-align: center; color: #4CAF50;'>XOR Cipher</h1>
        """, 
        unsafe_allow_html=True
    )
    with st.container(border=True):
        plaintext = bytes(st.text_area("Plaintext: ").encode())
        key = bytes(st.text_area("Key: ").encode())

        if st.button("Encrypt"):
            if plaintext == key:
                st.write("<div class='container message'>Plaintext should not be equal to the key</div>", unsafe_allow_html=True)
            elif len(plaintext.decode()) < len(key.decode()):
                st.write("<div class='container message'>Plaintext length should be equal or greater than the length of key</div>", unsafe_allow_html=True)
            else:
                encrypted = xor_encrypt(plaintext, key)
                if encrypted:  # Check if encryption was successful (non-empty ciphertext)
                    st.write("Ciphertext: ", encrypted.decode())
                    decrypted = xor_decrypt(encrypted, key)
                    st.write("Decrypted: ", decrypted.decode())

    
#Ceasar Cipher Page
if selected=="Ceasar Cipher":
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 43%;
        padding-right: 33%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    def encrypt_decrypt(text, shift_keys, ifdecrypt):
        result = ""
        shiftKeyLen = len(shift_keys)
        if shiftKeyLen == 0:
            st.warning("Please provide shift keys.")
            return result
        
        for start, char in enumerate(text):
            shift_key = shift_keys[start % shiftKeyLen] if not ifdecrypt else -shift_keys[start % shiftKeyLen]
            
            result += chr((ord(char) + shift_key - 32) % 94 + 32)
            st.write(start, char, shift_keys[start % shiftKeyLen], result[start])
            
        return result
        

    if __name__ == "__main__":
        st.markdown(
            """
            <h1 style='text-align: center; color: #4CAF50;'>Caesar Cipher</h1>
            """, 
            unsafe_allow_html=True
        )
        with st.container(border=True):
            text = st.text_area("Enter text to Encrypt", key=143)
            shift_keys_input = st.text_area("Enter shift keys separated by space")

            shift_keys = [int(key) for key in shift_keys_input.split() if key.strip()]

            if st.button("Encrypt"):
                encrypted = encrypt_decrypt(text, shift_keys, False)
                decrypted = encrypt_decrypt(encrypted, shift_keys, True)

                st.write("----------")
                st.write("Text:", text)
                st.write("Shift keys:" , " ".join(map(str, shift_keys)))
                st.write("Result:", encrypted)
                st.write("Decrypted text:", decrypted)

#Text Hashing Page
if selected=='Text Hashing':
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 43%;
        padding-right: 33%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    hash_algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

    def hash_text(text, algorithm):
        hash_func = getattr(hashlib, algorithm)()
        hash_func.update(text.encode('utf-8'))
        return hash_func.hexdigest()

    # Streamlit UI
    st.markdown(
        """
        <h1 style='text-align: center; color: #4CAF50;'>Text Hashing</h1>
        """, 
        unsafe_allow_html=True
    )

    with st.container(border=True):

        text_input = st.text_area("Enter the text to hash:")
        selected_algorithm = st.selectbox("Select Hashing Algorithm:", hash_algorithms)

        if st.button("Hash"):
            if text_input:
                hashed_text = hash_text(text_input, selected_algorithm)
                st.success(f"{selected_algorithm.upper()} Hash: {hashed_text}")
            else:
                st.warning("Please enter some text to hash.")

# XOR Block Cipher page
if selected=='XOR Block Cipher':
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 38%;
        padding-right: 33%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    def pad(data, block_size):    
        padding_length = block_size - len(data) % block_size  
        padding = bytes([padding_length] * padding_length)  
        return data + padding

    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    def xor_encrypt_block(plaintext_block, key):
        encrypted_block = b''
        for i in range(len(plaintext_block)):
            encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
        return encrypted_block

    def xor_decrypt_block(ciphertext_block, key):
        return xor_encrypt_block(ciphertext_block, key)

    def xor_encrypt(plaintext, key, block_size):
        encrypted_data = b''
        padded_plaintext = pad(plaintext, block_size)
        for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
            plaintext_block = padded_plaintext[i:i+block_size]
            encrypted_block = xor_encrypt_block(plaintext_block, key)
            encrypted_data += encrypted_block
        return encrypted_data

    def xor_decrypt(ciphertext, key, block_size):
        decrypted_data = b''
        for x, i in enumerate(range(0, len(ciphertext), block_size)):
            ciphertext_block = ciphertext[i:i+block_size]
            decrypted_block = xor_decrypt_block(ciphertext_block, key)
            decrypted_data += decrypted_block
        unpadded_decrypted_data = unpad(decrypted_data)
        return unpadded_decrypted_data

    def main():
        st.markdown(
            """
            <h3 style='text-align: center; color: #4CAF50;'>XOR Encryption and Decryption</h3>
            <p style='text-align: center; color: #4CAF50;'> Using Block Cipher </p>
            """, 
            unsafe_allow_html=True
        )

        with st.container(border=True):
            action = st.selectbox("Select Action", ["Encrypt", "Decrypt"])

        with st.container(border=True):
            if action == "Encrypt":
                plaintext = st.text_input("Enter the plaintext:")
                key = st.text_input("Enter the key:")
                block_size = st.selectbox("Select block size:", [8, 16, 32, 64, 128])

                if st.button("Encrypt"):
                    plaintext_bytes = bytes(plaintext.encode())
                    key_bytes = bytes(key.encode())
                    key_padded = pad(key_bytes, block_size)
                    encrypted_data = xor_encrypt(plaintext_bytes, key_padded, block_size)
                    st.success(f"Encrypted data: {encrypted_data.hex()}")

            if action == "Decrypt":
                ciphertext = st.text_input("Enter the ciphertext (in hexadecimal):")
                key = st.text_input("Enter the key:")
                block_size = st.selectbox("Select block size:", [8, 16, 32, 64, 128])

                if st.button("Decrypt"):
                    ciphertext_bytes = bytes.fromhex(ciphertext)
                    key_bytes = bytes(key.encode())
                    key_padded = pad(key_bytes, block_size)
                    decrypted_data = xor_decrypt(ciphertext_bytes, key_padded, block_size)
                    st.success(f"Decrypted data: {decrypted_data.decode()}")

    if __name__ == "__main__":
        main()


# File EncryptDecrypt Page
if selected=="File EncryptDecrypt":
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 40%;
        padding-right: 33%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    def generate_key():
        return Fernet.generate_key()

    def load_key(key):
        return Fernet(key)

    def encrypt_file(file, key, original_extension):
        data = file.read()
        fernet = load_key(key)
        encrypted_data = fernet.encrypt(data)
        return encrypted_data, original_extension

    def decrypt_file(file, key, original_extension):
        data = file.read()
        fernet = load_key(key)
        decrypted_data = fernet.decrypt(data)
        return decrypted_data, original_extension

    st.markdown(
        """
        <h1 style='text-align: center; color: #4CAF50;'>File Encrypter/Decrypter</h1>
        <p style='text-align: center; color: #4CAF50;'> Using Fernet </p>
        """, 
        unsafe_allow_html=True
    )
    with st.container(border=True):
        action = st.selectbox("Select Action", ["Encrypt", "Decrypt"])

        generated_key = None

        if action == "Encrypt":
            generated_key = generate_key()
        else:
            user_key = st.text_input("Enter Key")

        file = st.file_uploader("Upload a file")

        if st.button("Encrypt/Decrypt"):
            if file is not None and (action == "Encrypt" or (action == "Decrypt" and user_key)):
                if action == "Encrypt":
                    original_extension = os.path.splitext(file.name)[1]  # Get the original file extension
                    encrypted_data, original_extension = encrypt_file(file, generated_key, original_extension)
                    with io.BytesIO(encrypted_data) as encrypted_file:
                        st.download_button(label="Download Encrypted File", data=encrypted_file, file_name="encrypted_file" + original_extension, mime="application/octet-stream")
                    st.info("File encrypted successfully! This is the encryption key: {}".format(generated_key.decode()))
                elif action == "Decrypt":
                    original_extension = os.path.splitext(file.name)[1]  # Get the original file extension
                    decrypted_data, original_extension = decrypt_file(file, user_key, original_extension)
                    with io.BytesIO(decrypted_data) as decrypted_file:
                        st.download_button(label="Download Decrypted File", data=decrypted_file, file_name="decrypted_file" + original_extension, mime="application/octet-stream")


# RSA PAGE
if selected == "RSA":
    css = """
    /* Your custom CSS styles */
    .stButton {
        padding-left: 30%;
    }
    .stButton>button {
        background-color: #4CAF50; /* Green */
        width: 50%;
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }

    .stDownloadButton {
        padding-left: 30%;
    }

    .stDownloadButton>button {
        background-color: #4CAF50; /* Green */
        width: 50%;
        border: none;
        color: white;
        padding: 15px 32px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        transition-duration: 0.4s;
        cursor: pointer;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1), 0 6px 20px rgba(0, 0, 0, 0.1);
    }

    .stDownloadButton>button:hover {
        background-color: #45a049; /* Darker Green */
        color: black;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1), 0 12px 40px rgba(0, 0, 0, 0.1);
    }
    """

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

    def generate_keypair(key_size):
        key = RSA.generate(key_size)
        return key

    def encrypt_message(public_key, message):
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message

    def decrypt_message(private_key, encrypted_message):
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()
        return decrypted_message

    st.markdown(
        """
        <h1 style='text-align: center; color: #4CAF50;'>Text Encryption and Decryption</h1>
        <p style='text-align: center; color: #4CAF50;'> Using RSA </p>
        """, 
        unsafe_allow_html=True
    )

    with st.container(border=True):
        with st.container(border=True):
            # Key Generation
            st.markdown(
                """
                <h3 style='text-align: center; color: #4CAF50;'>Generate RSA Keypair</h3>
                """, 
                unsafe_allow_html=True
            )

            key_size = st.selectbox("Select key size", [1024, 2048, 4096])
            generate_button = st.button("Generate Keypair")

            if generate_button:
                keypair = generate_keypair(key_size)
                public_key = keypair.publickey().export_key().decode()
                private_key = keypair.export_key().decode()

                # Create a zip archive
                zip_buffer = BytesIO()
                with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
                    zip_file.writestr("public_key.pem", public_key.encode())
                    zip_file.writestr("private_key.pem", private_key.encode())

                # Reset the buffer position to the start
                zip_buffer.seek(0)

                # Offer the zip archive for download
                st.download_button(
                    label="Download Public and Private Keys",
                    data=zip_buffer.getvalue(),
                    file_name="public_private_keys.zip",
                    mime="application/zip",
                )

        action = st.selectbox("Select Action", ["Encrypt", "Decrypt"])

        if action == "Encrypt":
            # Encryption
            st.markdown(
                """
                <h3 style='text-align: center; color: #4CAF50;'>Encrypt Message</h3>
                """, 
                unsafe_allow_html=True
            )
            public_key_file = st.file_uploader("Upload Public Key:")
            message_to_encrypt = st.text_area("Enter message to encrypt:")
            encrypt_button = st.button("Encrypt")

            if encrypt_button:
                if public_key_file and message_to_encrypt:
                    public_key = RSA.import_key(public_key_file.read())
                    encrypted_message = encrypt_message(public_key, message_to_encrypt)
                    st.write("Encrypted Message:")
                    st.code(encrypted_message.hex())
        else:
            # Decryption
            st.markdown(
                """
                <h3 style='text-align: center; color: #4CAF50;'>Decrypt Message</h3>
                """, 
                unsafe_allow_html=True
            )
            private_key_file = st.file_uploader("Upload Private Key:")
            encrypted_message_input = st.text_area("Paste Encrypted Message:")
            decrypt_button = st.button("Decrypt")

            if decrypt_button:
                if private_key_file and encrypted_message_input:
                    private_key = RSA.import_key(private_key_file.read())
                    encrypted_message = bytes.fromhex(encrypted_message_input)
                    decrypted_message = decrypt_message(private_key, encrypted_message)
                    st.write("Decrypted Message:")
                    st.code(decrypted_message)
