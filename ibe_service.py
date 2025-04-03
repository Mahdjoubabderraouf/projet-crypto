from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.hash_module import Waters,Hash

from charm.core.engine.util import objectToBytes, bytesToObject
import hashlib

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
        g2_alpha = g2 ** alpha # secret

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
        return base64.b64encode(objectToBytes(obj,group)).decode('utf-8')

    def deserialize(self, data):
        """Deserialize stored crypto objects"""
        # If data is already a pairing Element, return it directly
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

    def deserialize_key(self, key_dict):
        """Convert serialized key back to crypto objects"""
        # Handle both dictionary and model object inputs
        if hasattr(key_dict, 'd0') and hasattr(key_dict, 'dn'):
            # Input is an object with attributes (like PrivateKeyModel)
            d0_data = key_dict.d0
            dn_data = key_dict.dn
        else:
            # Input is a dictionary
            d0_data = key_dict['d0']
            dn_data = key_dict['dn']
        
        # Deserialize d0
        if not isinstance(d0_data, str):
            d0 = d0_data
        else:
            d0 = bytesToObject(base64.b64decode(d0_data.encode('utf-8')), group)
            
        # Deserialize dn (list of elements)
        dn = []
        for dni_data in dn_data:
            if not isinstance(dni_data, str):
                dn.append(dni_data)
            else:
                dn.append(bytesToObject(base64.b64decode(dni_data.encode('utf-8')), group))
        
        return KeyObject(d0, dn)

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
        
        print(e ,"this is e")

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

        return {'A':A, 'B':B, 'C':C }

    def extract_key(self, params, ID, master_key):
        n = params['n']
        a = self.hash_to_list(ID, n)
        
        # Choose random r values for each position
        r = [group.random(ZR) for i in range(n)]
        
        # First part of private key
        hashID = master_key['g2_alpha']
        for i in range(n):
            hashID *= ((params['U'][i][int(a[i])])**r[i])
        
        # Second part of private key
        g_r = [params['g'] ** r[i] for i in range(n)]
        
        return {'d0': hashID, 'dn': g_r}

    def decrypt(self, params, cipher_text, dID):
        result = 1
        n = params['n']
        
        # Handle different input types
        if hasattr(cipher_text, 'A'):
            A = self.deserialize(cipher_text.A)
            B = self.deserialize(cipher_text.B)
            C = {i: self.deserialize(c) for i, c in enumerate(cipher_text.C)}
        else:
            A = cipher_text['A']
            B = cipher_text['B']
            C = cipher_text['C']
        
        if isinstance(dID, KeyObject):
            d0 = dID.d0
            dn = dID.dn
        elif hasattr(dID, 'd0') and hasattr(dID, 'dn'):
            key_obj = self.deserialize_key(dID)
            d0 = key_obj.d0
            dn = key_obj.dn
        else:
            d0 = dID['d0']
            dn = dID['dn']
        
        # Perform the multiple pairings
        for i in range(n):
            result *= pair(C[i], dn[i])
        M = A * (result / pair(B, d0))
        
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