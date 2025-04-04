
'''
Secure Identity Based Encryption Without Random Oracles
| From: Dan Boneh, Xaxier Boyen. 4.2 Secure IBE Using Admissible Hash Functions 
| Cited links and Installation guide can be found in Readme.md
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.hash_module import Waters,Hash
import hashlib

class Boneh_Boyen_IBE:
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

    def KeyGen(self, params,ID,master_key):
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

        return {'A':A, 'B':B, 'C':C }

    def decrypt(self,params, dID, cipher_text):
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

        #Parts of Cipher Text
        A = cipher_text['A']
        B = cipher_text['B']
        C = cipher_text['C']

        #Operations for decrypted cipher text
        for i in range(n):
            result *= pair(C[i], dID['dn'][i])
        M = A * (result / pair(B, dID['d0']))

        print("M", M)

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
if __name__ == "__main__":
    #dID = secret key
    #params = master public key
    from charm.toolbox.pairinggroup import PairingGroup, GT,G1
    group = PairingGroup('SS512')
    ibe = Boneh_Boyen_IBE(group)
    params, master_key = ibe.setup()
    ID = "alice@gmail.com"
    dID = ibe.KeyGen(params,ID, master_key)
    msg = group.random(GT)
    cipher_text = ibe.encrypt(params, ID, msg)
    decrypted_msg = ibe.decrypt(params, dID, cipher_text)
    print("Message: ", msg)
    print("Decrypted Message: ", decrypted_msg)
    print("Validation Message == Decrypted Message:",decrypted_msg == msg)
