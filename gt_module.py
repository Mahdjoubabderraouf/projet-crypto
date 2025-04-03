import hashlib
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

group = PairingGroup('SS512')  # Initialize the pairing group
gt_element = group.random(GT)

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
    ciphertext = symmetric_key.encrypt(plaintext_bytes)

# return them in object
    return {
        "ciphertext": ciphertext,
        "gt_element": gt_element
    }

def convert_gt_to_text(ciphertext):
    """
    Decrypts ciphertext using the given GT element.
    
    :param ciphertext: Encrypted message.
    :param gt_element: GT element used as the key.
    :return: Decrypted plaintext.
    """
    # Derive the symmetric AES key from GT element
    hash_key = hashlib.sha1(str(gt_element).encode()).digest()
    symmetric_key_dec = SymmetricCryptoAbstraction(hash_key)

    # Decrypt the message
    decrypted_text = symmetric_key_dec.decrypt(ciphertext)

    return decrypted_text.decode()

