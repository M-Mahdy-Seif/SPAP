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
import argparse
import socket, pickle


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

###########################################################################################
#########################   Registration Data   ###########################################
###########################################################################################

####################################  MSP   #############################################

SP_pub_key_X= 0xd9b43c10a0826fe9c27ec090595bc5a4b6c35a7329de05ff51e051c165e18a14
SP_pub_key_Y= 0x1014d58f4bcd5b6dca751c66edb59a9e345f6e12068596e06d34b61f743ca255
SP_pub_key=Point(SP_pub_key_X, SP_pub_key_Y, curve=P256)

############################   Custodian Entity  ###########################################

CE_pub_key_X= 0x1a4c34026a25cf84c6a92528fe216056fe5785106c811ecf95efcd9bf05e5374
CE_pub_key_Y= 0x65dcf37922f3ced73614a2056beebf6e22faa3ff334fc868d095e6a3f3bed14a
CE_pub_key=Point(CE_pub_key_X, CE_pub_key_Y, curve=P256)

###########################    U_w  ##########################################################

x_w_priv_key =  104840750407612104381194483925519319246165279019169541477707319833217658107192
X_W_pub_key_x= 0xaead1f8bc4b89f73a6f565eb04bacf00307a1de996af1ffe8e34ac901b2bbf9a
X_W_pub_key_y= 0x59017dd2f85f0d5aeac68ec84582629ead018e39d06e8ca2970346d378a1fbad
X_W_pub_key=Point(X_W_pub_key_x, X_W_pub_key_y, curve=P256)

y_w_priv_key =  98066942013586638802011552026428352579841430054489080884595402851103533963384
Y_W_pub_key_x = 0x4b1d86692199cb7eefbf97d47e679e93e47eb48c236209bb0e770a70f71897c5
Y_W_pub_key_y = 0xf3af816596105efe0948efd7021cc848fb1b89eb403d311244499b5687b4b1c8
Y_W_pub_key=Point(Y_W_pub_key_x, Y_W_pub_key_y, curve=P256)

ID_w =  23582550243065137620798238671238919330167628903024957569054493697599976596425
h_w =  66354809984204067060355682141906820477849853115588416285998356738747649574364
sigmaW =  77260357461491614707283408593963549180796615667187064458510411171564934326591

##########################   U_Z        ######################################################

x_Z_priv_key =  85475453542198315670871358709604750645268893020447172870357106807623876783437
y_Z_priv_key =  22927491274688101793471288929005428636474598315399028394313852140298041469249

X_Z_pub_key_X = 0x97d9e29474932b9938a9c73268b38ad91a2e09cbc5e0a1f155a90e258522214d
X_Z_pub_key_Y = 0xeba302f61c24692f55ad6a80a3c66d775a15df2301c319c0a443b72f272515b9
X_Z_pub_key=Point(X_Z_pub_key_X, X_Z_pub_key_Y, curve=P256)


Y_Z_pub_key_X= 0x46d6d449f486f5ec728fa3eb98a2f052355407ba26c6b315194de5ede87a808e
Y_Z_pub_key_Y= 0x88f157dec1f360f200bf92acc9c933e5acfdf65b06c4cc7a8a9a3719fec39d6f
Y_Z_pub_key=Point(Y_Z_pub_key_X, Y_Z_pub_key_Y, curve=P256)

ID_z =  9054617479589168434024179051773682339040210280620873265892784356049798198340
h_z =  47250319923856430156192528229107462257573065374664455159588801906934482258725
sigmaZ=  108148400459350256791468264537752687045626983425978932411129075842892859055545

##########################   Ava_m Transaction Key        #############################

Ava_m_Trans_pub_key_X= 0x9b2209430a4ea29090264f2014d3ecba9c2cec7c1dcdcf4ca41fbbff799113c0
Ava_m_Trans_pub_key_Y= 0x2a200827ebad3442d93d605f29eb278a56b56373724e083f9892dc264746a02
Ava_m_Trans_pub_key=Point(CE_pub_key_X, CE_pub_key_Y, curve=P256)

##########################   CE Transaction Key        #############################

CE_pub_key_X = 0x1a4c34026a25cf84c6a92528fe216056fe5785106c811ecf95efcd9bf05e5374
CE_pub_key_Y = 0x65dcf37922f3ced73614a2056beebf6e22faa3ff334fc868d095e6a3f3bed14a
CE_pub_key=Point(CE_pub_key_X, CE_pub_key_Y, curve=P256)

# The Socket programming
parser = argparse.ArgumentParser(description = 'Server for Ava_n')
args = parser.parse_args()

A = P256.G
B= A = P256.G
ExpiryTime=int.from_bytes(os.urandom(1024),'big')%P256.q
iv=Random.new().read(AES.block_size)
ECA_key=P256.G

def U_w_program():
    Uw_Socket = socket.socket()  # get instance
    host = '127.0.0.1'
    port = 5000  # socket server port number

    # look closely. The bind() function takes tuple as argument
    Uw_Socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    Uw_Socket.listen(10)    

    while True:
        conn, address = Uw_Socket.accept()  # accept new connection
        # print("Ava_n: Connection from: " + str(address))

        #Step 1: Receiving the identity of the sender and receiver from the Veghicle
        data = conn.recv(2048)         
        # print('Ava_n: Step 1: received from Ava_m: ')
        message=pickle.loads(data)
        # print(message)  # show in terminal
        P_1=Point(message[1].x, message[1].y, curve=P256)
        # print("Ava_n: P_1: ", P_1)

        message=Ava_nComputation(P_1)
        #Step 2: sending P_2, P_3, P_4, T_1, sigma_1, s_1 to AVa_m
        conn.send(pickle.dumps(message)) 
        # print("Ava_n: step 2: the sent data to the Ava_m", message)
        P_2=message[0]
        P_3=message[1]
        P_4=message[2]
        T_1=message[3]        

        #Step 3: Receiving P_5 || P_6 || T_2 || Sigma_2 || s_2
        data = conn.recv(2048)
        # print('Ava_n: Step 3: received from Ava_m: ')
        message=pickle.loads(data)
        # print(message)  # show in terminal
        P_5=Point(message[0].x, message[0].y, curve=P256)
        P_6=Point(message[1].x, message[1].y, curve=P256)
        T_2=Point(message[2].x, message[2].y, curve=P256)
        sigma_2=message[3]
        s_2=message[4]

        Ava_mVerificationComputation(P_1,P_2,P_3,P_4,P_5,P_6,T_2,sigma_2,s_2)

        #Step 4: Final Msg for time calculation
        message="Final Goodbye"
        conn.send(pickle.dumps(message))

def Ava_mVerificationComputation(P_1,P_2,P_3,P_4,P_5,P_6,T_2,sigma_2,s_2):       
    I_w=Hash(P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,P_6.x,P_6.y,T_2.x,T_2.y)
    
    # print("The verification of sigma2",sigma_2*P256.G==(I_w*P_6+I_w*P_5+P_1))
    # print("The verification of s2",s_2*SP_pub_key==(I_w*P_5+T_2))

# Ava_n computation
def Ava_nComputation(P_1):       
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
    return P_2, P_3, P_4, T_1, sigma_1, s_1 
if __name__ == '__main__':
    U_w_program()




