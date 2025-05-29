import os
import argparse
import tempfile
import shutil
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def derive_key(password, salt, key_len=32):
    # Increased iterations for stronger key derivation
    return PBKDF2(password.encode('utf-8'), salt, dkLen=key_len, count=500_000, hmac_hash_module=SHA256)

def encrypt_file(input_path, output_path, key_sources):
    print("🔐 Starting encryption...")

    password = ""
    for path in key_sources:
        if not os.path.exists(path):
            print(f"❌ Key file not found: {path}")
            return False
        try:
            with open(path, "rb") as f:
                password += f.read().decode(errors="ignore")
        except Exception as e:
            print(f"❌ Error reading key file {path}: {e}")
            return False

    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)

    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        print(f"❌ Error reading input file {input_path}: {e}")
        return False

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    try:
        with open(output_path, "wb") as out:
            out.write(salt + cipher.nonce + tag + ciphertext)
    except Exception as e:
        print(f"❌ Error writing output file {output_path}: {e}")
        return False

    print(f"[+] ✅ Encryption complete. Saved to: {output_path}")
    return True

def decrypt_file(encrypted_path, key_sources, output_path):
    print("🔓 Starting decryption...")

    if not os.path.exists(encrypted_path):
        print(f"❌ Encrypted file not found: {encrypted_path}")
        return False

    password = ""
    for path in key_sources:
        if not os.path.exists(path):
            print(f"❌ Key file not found: {path}")
            return False
        try:
            with open(path, "rb") as f:
                password += f.read().decode(errors="ignore")
        except Exception as e:
            print(f"❌ Error reading key file {path}: {e}")
            return False

    try:
        with open(encrypted_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"❌ Error reading encrypted file {encrypted_path}: {e}")
        return False

    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_path, "wb") as out:
            out.write(plaintext)
    except ValueError:
        print("❌ Decryption failed: MAC check failed")
        return False
    except Exception as e:
        print(f"❌ Error writing decrypted file {output_path}: {e}")
        return False

    print(f"[+] ✅ Decryption successful. Output saved to: {output_path}")
    return True

def combine_files_with_delimiter(file_paths, combined_path, delimiter=b'\n---FILE_BOUNDARY---\n'):
    try:
        with open(combined_path, "wb") as out:
            for i, fpath in enumerate(file_paths):
                with open(fpath, "rb") as f:
                    out.write(f.read())
                if i < len(file_paths) - 1:
                    out.write(delimiter)
        return True
    except Exception as e:
        print(f"❌ Error combining files: {e}")
        return False

def main():
    print("🔐 Welcome to Perfect Encryptor/Decryptor Tool")

    try:
        num_files = int(input("📁 How many input files do you want to use? (1 or more): ").strip())
        if num_files < 1:
            print("❌ Number of files must be at least 1.")
            return
    except ValueError:
        print("❌ Invalid number entered.")
        return

    input_files = []
    for i in range(num_files):
        path = input(f"📝 Enter path for input file #{i+1}: ").strip()
        if not os.path.exists(path):
            print(f"❌ File not found: {path}")
            return
        input_files.append(path)

    action = input("🔄 Do you want to (e)ncrypt or (d)ecrypt?: ").strip().lower()
    output_path = input("💾 Enter desired output file path: ").strip()

    if action == 'e':
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            combined_path = tmp_file.name
        if not combine_files_with_delimiter(input_files, combined_path):
            return
        if encrypt_file(combined_path, output_path, input_files):
            try:
                os.remove(combined_path)
            except Exception as e:
                print(f"⚠️ Warning: Could not delete temporary file: {e}")
    elif action == 'd':
        if len(input_files) < 2:
            print("❌ For decryption, provide the encrypted file followed by key files.")
            return
        encrypted_file = input_files[0]
        key_files = input_files[1:]
        decrypt_file(encrypted_file, key_files, output_path)
    else:
        print("❌ Invalid action. Choose 'e' for encrypt or 'd' for decrypt.")

if __name__ == "__main__":
    main()