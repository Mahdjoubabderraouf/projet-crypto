from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from ibe_service import IBEService
import json
# ...existing code...
# ...existing code...

def main():
    # Initialize the pairing group
    group = PairingGroup('SS512')
    
    # Initialize the IBE service
    ibe = IBEService(group)
    
    print("Setting up IBE parameters and master key...")
    # Setup - generates system parameters and master key
    params, master_key = ibe.setup()
    
    # For demonstration, serialize parameters and master key
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
    
    # Create a human-readable message
    original_message = "hello world"
    print("Original message:", original_message)
    
    # Encode the message into bytes and hash it to ZR
    message_bytes = original_message.encode('utf-8')
    hashed_message = group.hash(message_bytes, ZR)
    
    # Map the hashed message to GT using a pairing operation
    g = params['g']  # Retrieve a generator from the parameters
    message = pair(g, g) ** hashed_message
    print("Mapped message (GT element):", ibe.serialize(message))
    
    # Encrypt the message for the identity
    print(f"Encrypting message for identity: {user_id}")
    cipher_text = ibe.encrypt(params, user_id, message)
    
    # Serialize the cipher text for display
    serialized_cipher = {
        'A': ibe.serialize(cipher_text['A']),
        'B': ibe.serialize(cipher_text['B']),
        'C': {str(i): ibe.serialize(c) for i, c in cipher_text['C'].items()}
    }
    print("Encrypted message:")
    print(json.dumps(serialized_cipher, indent=2))
    
    # Decrypt the message using the private key
    print("Decrypting message with private key...")
    deserialized_key = ibe.deserialize_key(serialized_private_key)
    decrypted_message = ibe.decrypt(params, cipher_text, deserialized_key)
    
    print("Decrypted message (GT element):", ibe.serialize(decrypted_message))
    
    # Verify the decryption succeeded
    if decrypted_message == message:
        print("Success! Decryption recovered the original message.")
    else:
        print("Error: Decryption failed to recover the original message.")
        
 # Retrieve the original message from the ciphertext
    retrieved_original_message = cipher_text['original_message']
    print("Retrieved original message:", retrieved_original_message)
    
    # Verify the decryption succeeded
    if decrypted_message == message and retrieved_original_message == original_message:
        print("Success! Decryption recovered the original message.")
    else:
        print("Error: Decryption failed to recover the original message.")

    
    
if __name__ == "__main__":
    main()