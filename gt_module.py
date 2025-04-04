import hashlib
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

group = PairingGroup('SS512')  # Initialize the pairing group
gt_element = group.random(GT)
cipher_text=''


def convert_text_to_gt(plaintext: str):
    """
    Encrypts plaintext and returns (ciphertext, GT element).
    
    :param plaintext: The message to encrypt.
    :return: (ciphertext, gt_element)
    """
    plaintext_bytes = plaintext.encode()  # Convert text to bytes

    # Derive a symmetric AES key from GT element
    hash_key = hashlib.sha1(str(gt_element).encode()).digest()
    symmetric_key = SymmetricCryptoAbstraction(hash_key)

    # Encrypt plaintext using AES
    cipher_text = symmetric_key.encrypt(plaintext_bytes)

# return them in object
    return {
        "ciphertext": cipher_text,
        "gt_element": gt_element
    }

def convert_gt_to_text(decrypted_key):
    """
    Decrypts decrypted_key using the given GT element.
    
    :param decrypted_key: Encrypted message.

    :return: Decrypted plaintext.
    """
    # Derive the symmetric AES key from GT element
    
    
    hash_key = hashlib.sha1(str(decrypted_key).encode()).digest()
    symmetric_key_dec = SymmetricCryptoAbstraction(hash_key)

    # Decrypt the message
    decrypted_text = symmetric_key_dec.decrypt(cipher_text)

    return decrypted_text.decode()

