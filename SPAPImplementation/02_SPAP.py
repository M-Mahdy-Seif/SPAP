from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey

from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Cipher import AES

import hashlib

import os 

from mod import Mod

def Hash(*dataListByte):
    h = hashlib.new('sha256')
    Mydata=b""
    for data in dataListByte:
        #print("Data: ",data)
        Mydata = Mydata + data.to_bytes(32, 'big')
    h.update(Mydata)
    HashResult=h.hexdigest()
    Hash_value=int(HashResult,16)%P256.q
    return Hash_value

def xor_integers(a: int, b: int) -> int:
    """
    Computes the bitwise XOR of two integers.
    """
    return a ^ b

#######################################################################################
#############       The registration phase          ###################################
#######################################################################################
#The Generation of the MSP keys 
SP_priv_key, SP_pub_key = keys.gen_keypair(curve.P256)
print("MSP Public Key: SP_pub_key: ", SP_pub_key)

#The Generation of the Metaverse user w keys and Identity
x_w_priv_key, X_W_pub_key = keys.gen_keypair(curve.P256)
y_w_priv_key, Y_W_pub_key = keys.gen_keypair(curve.P256)
ID_w=int.from_bytes(os.urandom(1024),'big')%P256.q

h_w=Hash(ID_w,X_W_pub_key.x,X_W_pub_key.y,Y_W_pub_key.x,Y_W_pub_key.y,SP_pub_key.x,SP_pub_key.y)
sigmaW=(SP_priv_key+h_w*y_w_priv_key)%P256.q

print("Metaverse User W: x_w_priv_key: ", x_w_priv_key)
print("Metaverse User W: X_W_pub_key: ", X_W_pub_key)
print("Metaverse User W: y_w_priv_key: ", y_w_priv_key)
print("Metaverse User W: Y_W_pub_key: ", Y_W_pub_key)
print("Metaverse User W: ID_w: ", ID_w)

print("Metaverse User W: h_w: ", h_w)
print("Metaverse User W: sigmaW: ", sigmaW)

#print("The verification of sigmaW",sigmaW*P256.G==(SP_pub_key+h_w*Y_W_pub_key))

#The Generation of the Metaverse user Z keys and Identity
x_Z_priv_key, X_Z_pub_key = keys.gen_keypair(curve.P256)
y_Z_priv_key, Y_Z_pub_key = keys.gen_keypair(curve.P256)
ID_z=int.from_bytes(os.urandom(1024),'big')%P256.q

h_z=Hash(ID_z,X_Z_pub_key.x,X_Z_pub_key.y,Y_Z_pub_key.x,Y_Z_pub_key.y,SP_pub_key.x,SP_pub_key.y)
sigmaZ=(SP_priv_key+h_z*y_Z_priv_key)%P256.q

print("Metaverse User Z: x_Z_priv_key: ", x_Z_priv_key)
print("Metaverse User Z: X_Z_pub_key: ", X_Z_pub_key)
print("Metaverse User Z: y_Z_priv_key: ", y_Z_priv_key)
print("Metaverse User Z: Y_Z_pub_key: ", Y_Z_pub_key)
print("Metaverse User Z: ID_z: ", ID_z)

print("Metaverse User Z: h_z: ", h_z)
print("Metaverse User Z: sigmaZ: ", sigmaZ)

#print("The verification of sigmaZ",sigmaZ*P256.G==(SP_pub_key+h_z*Y_Z_pub_key))

#The Generation of the Ava_m Transaction key 
Ava_m_Trans_priv_key, Ava_m_Trans_pub_key = keys.gen_keypair(curve.P256)
print("Avatar m Transaction Key: Ava_m_Trans_pub_key: ", Ava_m_Trans_pub_key)


#The Generation of the CE keys 
CE_priv_key, CE_pub_key = keys.gen_keypair(curve.P256)
print("CE Public Key: CE_pub_key: ", CE_pub_key)


############################################################################
##########  The authentication between Ava_m and Ava_n  ####################
############################################################################

# Ava_m computation  
rng_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

P_1=rng_1*X_W_pub_key

# Ava_n computation  
rng_1_prime = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_2_prime = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_3_prime = int.from_bytes(os.urandom(1024),'big')%P256.q

P_2=rng_1_prime*X_Z_pub_key
P_3=rng_2_prime*SP_pub_key
P_4=rng_2_prime*h_z*Y_Z_pub_key
T_1=rng_3_prime*SP_pub_key

I_z=Hash(P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,T_1.x,T_1.y)

sigma_1=(I_z*rng_2_prime*sigmaZ+rng_1_prime*x_Z_priv_key)%P256.q
s_1=(rng_2_prime*I_z+rng_3_prime)%P256.q

### Ava_m Computation ###

# print("The verification of sigma1",sigma_1*P256.G==(I_z*P_3+I_z*P_4+P_2))
# print("The verification of s1",s_1*SP_pub_key==(I_z*P_3+T_1))

P_5=rng_2*SP_pub_key
P_6=rng_2*h_w*Y_W_pub_key
T_2=rng_3*SP_pub_key

I_w=Hash(P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,P_6.x,P_6.y,T_2.x,T_2.y)
sigma_2=(I_w*rng_2*sigmaW+rng_1*x_w_priv_key)%P256.q
s_2=(rng_2*I_w+rng_3)%P256.q

### Ava_n Computation ###

# print("The verification of sigma2",sigma_2*P256.G==(I_w*P_6+I_w*P_5+P_1))
# print("The verification of s2",s_2*SP_pub_key==(I_w*P_5+T_2))



#################################################################################
####################### Ava_m authentication with the CE 

# CE computation  
rng_4 = int.from_bytes(os.urandom(1024),'big')%P256.q
PE=rng_4*P256.G


# Ava_m Computation
rng_1_prime_prime = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_2_prime_prime = int.from_bytes(os.urandom(1024),'big')%P256.q
rng_3_prime_prime = int.from_bytes(os.urandom(1024),'big')%P256.q

P_7=rng_1_prime_prime*X_W_pub_key
P_8=rng_2_prime_prime*SP_pub_key
P_9=rng_2_prime_prime*h_w*Y_W_pub_key
T_3=rng_3_prime_prime*SP_pub_key

I_w_prime=Hash(PE.x, PE.y, P_1.x,P_1.y,P_2.x,P_2.y,P_7.x,P_7.y,P_8.x,P_8.y,P_9.x,P_9.y,T_3.x,T_3.y)

sigma_3=(I_w_prime*rng_2_prime_prime*sigmaW+rng_1_prime_prime*x_w_priv_key)%P256.q
s_3=(rng_2_prime_prime*I_w_prime+rng_3_prime_prime)%P256.q

### CE Computation ###

# print("The verification of sigma_3",sigma_3*P256.G==(I_w_prime*P_9+I_w_prime*P_8+P_7))
# print("The verification of s3",s_3*SP_pub_key==(I_w_prime*P_8+T_3))

a = int.from_bytes(os.urandom(1024),'big')%P256.q
V = a*P256.G

k=P256.q.bit_length()
x_w=Ava_m_Trans_priv_key
# Decompose x_w into its binary bits (little-endian order: s_0 is LSB)
s_list = [(x_w >> i) & 1 for i in range(k)]

r_list=[]
for i in range(k):
    r_i=int.from_bytes(os.urandom(1024),'big')%P256.q
    r_list.append(r_i)

r = sum((2 ** i) * r_list[i] for i in range(k))
# Compute C_i = r_i * P + s_i * V
C_list = []
for i in range(k):
    riP = r_list[i] * P256.G
    siV = s_list[i] * V
    Ci = riP + siV  # EC point addition
    C_list.append(Ci)

SmartContractAddress=int.from_bytes(os.urandom(1024),'big')%P256.q



# for i in range(k):
#     C_Acc+(2 ** i) * C_list[i]
C_Acc = None  # point at infinity (identity element)

for i in range(k):
    scalar = 2 ** i
    term = scalar * C_list[i]  # scalar multiplication of EC point
    if C_Acc is None:
        C_Acc = term
    else:
        C_Acc = C_Acc + term  # EC point addition

# print("The verification of C",C_Acc==(r*P256.G+a*Ava_m_Trans_pub_key))

###########################################################################
######## CROT #########################################################

K_s = int.from_bytes(os.urandom(1024),'big')%P256.q

iv = Random.new().read(AES.block_size)


K_i_zero_list = []
K_i_one_list = []
p_i_list = []
Message_encrypted_i_ZeroList =[]
Message_encrypted_i_OneList = []
for i in range(k):
    Res_a_C_list=a*C_list[i]
    Res_K_i_one=a*C_list[i] - a*V
    K_i_zero = Hash(Res_a_C_list.x,Res_a_C_list.y)
    K_i_one = Hash(Res_K_i_one.x,Res_K_i_one.y)

    Message_i=int.from_bytes(os.urandom(1024),'big')%P256.q
    M_i_Zero=xor_integers(Message_i, Hash(K_s,int.from_bytes(b'\x00' * 1024, 'big')%P256.q))
    M_i_One=xor_integers(Message_i, Hash(K_s,int.from_bytes(b'\xFF' * 1024, 'big')%P256.q))

    ENC = AES.new(K_i_zero.to_bytes(32,'big'), AES.MODE_CBC, iv)
    Message_encrypted_i_Zero=ENC.encrypt(M_i_Zero.to_bytes(32,'big'))
    ENC = AES.new(K_i_one.to_bytes(32,'big'), AES.MODE_CBC, iv)
    Message_encrypted_i_One=ENC.encrypt(M_i_One.to_bytes(32,'big'))

    I_i_Zero = Hash (M_i_Zero,SmartContractAddress, P_1.x,P_1.y, P_2.x,P_2.y,P_7.x,P_7.y)
    I_i_One  = Hash (M_i_One,SmartContractAddress, P_1.x,P_1.y, P_2.x,P_2.y,P_7.x,P_7.y)
    Z_i_Zero = sigma_3+I_i_Zero*CE_priv_key
    Z_i_One = sigma_3+I_i_One*CE_priv_key

    P_i=xor_integers(K_i_zero, K_i_one) 
    K_i_zero_list.append(K_i_zero)
    K_i_one_list.append(K_i_one)    
    p_i_list.append(P_i)
    Message_encrypted_i_ZeroList.append(Message_encrypted_i_Zero)
    Message_encrypted_i_OneList.append(Message_encrypted_i_One)

#############################################################################
##########      Computation of K_i,si   #####################################

K_i_si_list = []
for i in range(k):
    Res_list_V=r_list[i]* V
    K_i_si=Hash(Res_list_V.x,Res_list_V.y)
    P_i_prime=  xor_integers(K_i_si,s_list[i]*p_i_list[i])
    # print("The verification of Pi_prime",P_i_prime==K_i_zero_list[i])
    K_i_si_list.append(P_i)