from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.hash_module import Waters,Hash
import hashlib
from charm.core.engine.util import objectToBytes, bytesToObject

import base64
import os
import json
from dotenv import load_dotenv

load_dotenv()

class KeyObject:
    """Helper class to store deserialized keys with attribute access"""
    def __init__(self, d0, dn):
        self.d0 = d0
        self.dn = dn

class IBEService:
    def __init__(self, groupObj):
        global group
        group = groupObj

    def setup(self):
        """
        Setup algorithm for Boneh-Boyen Identity-Based Encryption.

        Returns:
            params (dict): System parameters including public parameters.
            master_key (dict): Master secret key.
        """
        #Pick a random alpha from Zp
        alpha = group.random(ZR) # secret 

        g = group.random(G1) # 
        g1 = g**alpha # public 

        g2 = group.random(G2) # public
        g2_alpha = g2 ** alpha # public

        # Select a random hash function key from the family of hash functions
        k = group.random(ZR) 

        # n x s matrix constructions
        n = 3
        s = 2
        U = [[group.random(G2) for _ in range(s)] for _ in range(n)]

        #Precompute g1 and g2 pairing computations
        e = pair(g1,g2)

        params = { 'g': g, 'g1':g1, 'g2':g2,'U':U,'k':k,'e':e,'n':n,'s':s }
        master_key = { 'g2_alpha':g2_alpha }

        return (params, master_key)
    
    def serialize(self, obj):
        """Serialize crypto objects for storage"""
        return base64.b64encode(objectToBytes(obj, group)).decode('utf-8')

    def deserialize(self, data):
        """Deserialize stored crypto objects"""
        return bytesToObject(base64.b64decode(data.encode('utf-8')), group)
    
    def serialize_response(self, obj):
        """Serialize crypto objects for API responses"""
        if isinstance(obj, (int, str, float, bool, list, dict)):
            return obj
        elif hasattr(obj, '__dict__'):
            return {k: self.serialize_response(v) for k, v in vars(obj).items()}
        else:
            return self.serialize(obj)  # Use existing base64 serialization
    
    def serialize_key(self, key_dict):
        """Convert private key components to serializable format"""
        return {
            'd0': base64.b64encode(objectToBytes(key_dict['d0'], group)).decode('utf-8'),
            'dn': [base64.b64encode(objectToBytes(dni, group)).decode('utf-8') 
                for dni in key_dict['dn']]
        }

    def deserialize_key(self, serialized_key):
        """Convert serialized private key back to Charm Element objects"""
        try:
            # Deserialize d0 (main private key component)
            d0_bytes = base64.b64decode(serialized_key['d0'])
            d0 = bytesToObject(d0_bytes, group)
            
            # Deserialize dn components (delegated keys)
            dn = []
            for dni_b64 in serialized_key['dn']:
                dni_bytes = base64.b64decode(dni_b64)
                dni = bytesToObject(dni_bytes, group)
                dn.append(dni)
                
            return {'d0': d0, 'dn': dn}
            
        except Exception as e:
            raise ValueError(f"Failed to deserialize private key: {str(e)}")
    
    def extract_key(self, params, ID, master_key):
        """
        Key Generation algorithm for Boneh-Boyen Identity-Based Encryption.

        Args:
            params (dict): System parameters including public parameters.
            ID (str): Identity string.
            master_key (dict): Master secret key.

        Returns:
            dict: User secret key.
        """

        n = params['n']

        #Hash identify to {0,1} based on group and length 'n'
        a = self.hash_to_list(ID,n)

        #Choose a random r form Zp
        r = [group.random(ZR) for i in range(n)]

        #First part of the private key 
        hashID = master_key['g2_alpha']
        for i in range(n):
            hashID *= ((params['U'][i][int(a[i])])**r[i])

        #Second part of private key
        g_r = [params['g'] ** r[i] for i in range(n)]

        return { 'd0':hashID, 'dn':g_r }

    def encrypt(self, params,ID, M):
        """
        Encryption algorithm for Boneh-Boyen Identity-Based Encryption.

        Args:
            params (dict): System parameters including public parameters.
            ID (str): Identity string.
            M (GT): Message to be encrypted.

        Returns:
            dict: Encrypted cipher text.
        """
        n = params['n']
        e = params['e']
        g = params['g']
        U = params['U']

        #Hash identify to {0,1} based on group and length 'n'
        a = self.hash_to_list(ID,n)

        #Pick a random t from Zp
        t = group.random(ZR)

        #Operations for Cipher texts
        A =  (e ** t) * M
        B = g ** t
        C = {}
        for i in range(n):
            C[i] = ((U[i][int(a[i])])**t)
            
        print({'A':A, 'B':B, 'C':C })
        return {'A':A, 'B':B, 'C':C }
    
    def ensure_pairing_element(self, obj, element_type=G1):
        """
        Convert an integer or other value to a pairing element if needed.
        """
        if hasattr(obj, 'getGroupType') and obj.getGroupType() is not None:
            # The object is already a group element
            return obj
        if isinstance(obj, int):
            # Convert an integer to ZR and then to the target element type (G1, G2, GT)
            zr_elem = group.init(ZR, obj)
            return group.init(element_type, zr_elem)
        return group.init(element_type, obj)

    def decrypt(self, params, dID, cipher_text):
        """
        Decryption algorithm for Boneh-Boyen Identity-Based Encryption.

        Args:
            params (dict): System parameters including public parameters.
            dID (dict): User secret key.
            cipher_text (dict): Encrypted cipher text.

        Returns:
            GT: Decrypted message.
        """
        result = 1
        n = params['n']

        # Extract parts of Cipher Text
        A = cipher_text['A']
        B = cipher_text['B']
        C = cipher_text['C']
        
        # # Ensure all elements are proper pairing elements
        # A = self.ensure_pairing_element(A, GT)
        # B = self.ensure_pairing_element(B, G1)
        
        # # Ensure each C element is a pairing element
        # for i in range(n):
        #     C[i] = self.ensure_pairing_element(C[i], G1)
            

        # Perform decryption operations
        for i in range(n):
            result *= pair(C[i], dID['dn'][i])  # Pairing operation on C[i] and dID['dn'][i]
        
        M = A * (result / pair(B, dID['d0']))  # Final decryption step using A, B, and result

        # Return the decrypted message (it will be a pairing element in GT)
        return M



    
    def hash_to_list(self,strID,n):
        """
        Hashing Algorithm for "a" list

        Args:
            strID: Identity String
            n: length of "a" list

        Returns:
           binary_list: list which encoded to binary
        """
        hash_algo = hashlib.sha512()
        hash_algo.update(strID.encode('utf-8'))
        hash_output = hash_algo.digest()
        binary_str = "".join(format(byte, '08b') for byte in hash_output)[:n]
        binary_list = [int(bit) for bit in binary_str]
        return binary_list