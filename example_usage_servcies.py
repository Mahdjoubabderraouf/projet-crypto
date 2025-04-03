from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from ibe_service import IBEService
import json

def main():
    # Initialize the pairing group
    group = PairingGroup('SS512')
    
    # Initialize the IBE service
    ibe = IBEService(group)
    
    print("Setting up IBE parameters and master key...")
    # Setup - generates system parameters and master key
    params, master_key = ibe.setup()
    
    # For demonstration, serialize parameters and master key
    # In a real system, these would be securely stored
    serialized_params = ibe.serialize_response(params)
    serialized_master_key = ibe.serialize_response(master_key)
    
    print("Parameters and master key generated.")
    
    # User identity
    user_id = "alice@example.com"
    print(f"Extracting private key for identity: {user_id}")
    
    # Extract a private key for the given identity
    
    
    private_key = ibe.extract_key(params, user_id, master_key)
    serialized_private_key = ibe.serialize_key(private_key)
    
    print(f"Private key generated for {user_id}:")
    print(json.dumps(serialized_private_key, indent=2))
    
    # Create a message to encrypt
    # In IBE, messages are elements of the GT group
    message = group.random(GT)
    print("Original message (GT element):", ibe.serialize(message))
    
    # Encrypt the message for the identity
    print(f"Encrypting message for identity: {user_id}")
    cipher_text = ibe.encrypt( params,user_id, message)
    
    # Serialize the cipher text for display
    # Manually serialize each component of the cipher_text
    serialized_cipher = {
        'A': ibe.serialize(cipher_text['A']),
        'B': ibe.serialize(cipher_text['B']),
        'C': {str(i): ibe.serialize(c) for i, c in cipher_text['C'].items()}
    }
    print("Encrypted message:")
    print(json.dumps(serialized_cipher, indent=2))
    
    # Decrypt the message using the private key
    print("Decrypting message with private key...")
    
    # First, deserialize the private key (simulating retrieval from storage)
    deserialized_key = ibe.deserialize_key(serialized_private_key)
    
    # Decrypt
    decrypted_message = ibe.decrypt(params, cipher_text, deserialized_key)
    
    print("Decrypted message (GT element):", ibe.serialize(decrypted_message))
    
    # Verify the decryption succeeded
    if decrypted_message == message:
        print("Success! Decryption recovered the original message.")
    else:
        print("Error: Decryption failed to recover the original message.")
    
    # Example of sharing data between users
    print("\n--- Example: Sharing data between users ---")
    
    # Another user
    recipient_id = "bob@example.com"
    print(f"Extracting private key for identity: {recipient_id}")
    
    # Extract a private key for the recipient
    recipient_key = ibe.extract_key(params, recipient_id, master_key)
    
    # Alice encrypts a message for Bob
    bob_message = group.random(GT)
    print(f"Alice encrypting message for Bob ({recipient_id})")
    bob_cipher = ibe.encrypt(params,recipient_id, bob_message)
    
    # Manually serialize Bob's cipher for display
    serialized_bob_cipher = {
        'A': ibe.serialize(bob_cipher['A']),
        'B': ibe.serialize(bob_cipher['B']),
        'C': {str(i): ibe.serialize(c) for i, c in bob_cipher['C'].items()}
    }
    print("Encrypted message for Bob:")
    print(json.dumps(serialized_bob_cipher, indent=2))
    
    # Bob decrypts the message with his private key
    print("Bob decrypting message with his private key...")
    bob_decrypted = ibe.decrypt(params, bob_cipher, recipient_key)
    
    if bob_decrypted == bob_message:
        print("Success! Bob successfully decrypted Alice's message.")
    else:
        print("Error: Bob failed to decrypt Alice's message.")

if __name__ == "__main__":
    main()
