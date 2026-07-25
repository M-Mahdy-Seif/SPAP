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
import time

import threading
import csv

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

#########################################################################################
#########################   Registration Data   #########################################
#########################################################################################

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

parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='CA server to connect to') 
args = parser.parse_args()


def AVA_program():
    Ava_mSocket = socket.socket()  # get instance  

    # get the hostname
    bind_address = '127.0.0.1'
    port = 5000  # initiate port no above 1024
    host = args.connect # CA server
        
    Ava_mSocket.connect((bind_address, port))  # connect to the server

    # step 1: sending Identity of the sender and receiver to the Ava_n
    data=SendID_HelloMsg_P1()
    rng_1=data[0]
    rng_2=data[1]
    rng_3=data[2]
    MsgToSend=  data[3:]
    P_1=data[4]

    # Start the timer
    start_time = time.perf_counter()

    Ava_mSocket.send(pickle.dumps(MsgToSend))    
    # print('Ava_m: step 1: sent to Ava_n: ' + str(MsgToSend))

    # step 2: Receiving P_2, P_3, P_4, T_1, sigma_1, s_1  from Ava_n
    data = Ava_mSocket.recv(2048)
    message=pickle.loads(data)
    # print('Ava_m: step 2: received from Ava_n: ', message)
    # print(message)  # show in terminal
    P_2=Point(message[0].x, message[0].y, curve=P256)
    P_3=Point(message[1].x, message[1].y, curve=P256)
    P_4=Point(message[2].x, message[2].y, curve=P256)
    T_1=Point(message[3].x, message[3].y, curve=P256)
    sigma_1=message[4]
    s_1=message[5]
    dataToSent=Ava_mVerificationComputation(P_1,P_2,P_3,P_4,T_1,sigma_1,s_1,rng_1,rng_2,rng_3)

    #Step 3: sending P_5||P_6||T_2||sigma_2||S_2 to Ava_n
    Ava_mSocket.send(pickle.dumps(dataToSent)) 
    # print("Ava_m: step 3: the sent data to the Ava_n", dataToSent)

    data = Ava_mSocket.recv(2048)

    # End the timer
    end_time = time.perf_counter()

    # Calculate duration
    duration = end_time - start_time

    message=pickle.loads(data)
    # print('Ava_m: step 4: received from Ava_n: ', message)
    # print(f"Round-trip time: {duration:.6f} seconds")
    # print(f"Latency: {duration:.6f} sec")
    # latencies.append(duration)

# Ava_m computation and Verification
def Ava_mVerificationComputation(P_1,P_2,P_3,P_4,T_1,sigma_1,s_1,rng_1,rng_2,rng_3):       
    I_z=Hash(P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,T_1.x,T_1.y)
    
    # print("The verification of sigma1 inside the function:",sigma_1*P256.G==(I_z*P_3+I_z*P_4+P_2))
    # print("The verification of s1 inside the function:",s_1*SP_pub_key==(I_z*P_3+T_1))

    P_5=rng_2*SP_pub_key
    P_6=rng_2*h_w*Y_W_pub_key
    T_2=rng_3*SP_pub_key

    I_w=Hash(P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,P_6.x,P_6.y,T_2.x,T_2.y)
    sigma_2=(I_w*rng_2*sigmaW+rng_1*x_w_priv_key)%P256.q
    s_2=(rng_2*I_w+rng_3)%P256.q
    return P_5, P_6, T_2, sigma_2, s_2


# Ava_m computation for r_1, r_2, r_3, P_1
def SendID_HelloMsg_P1():     
    rng_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
    rng_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
    rng_3 = int.from_bytes(os.urandom(1024),'big')%P256.q
    Msg = "HelloMsg"
    P_1=rng_1*X_W_pub_key
    return rng_1, rng_2, rng_3, Msg, P_1

def Send_A_IncrementedNonce():
    return A, TMA_Identity

def computeSigma2_s1():
    return sigma_2, s_1

# def worker(clientID):
#     # print("Client", clientID, "started")
#     AVA_program()
#     # print("Client", clientID, "finished")

# if __name__ == '__main__':
#     threads = []
#     latencies = []
#     NUM_CLIENTS = 90

#     experiment_start = time.perf_counter()
#     for i in range(NUM_CLIENTS):
#         t = threading.Thread(
#             target=worker,
#             args=(i,)
#         )
#         t.start()
#         threads.append(t)

#     for t in threads:
#         t.join()
#     experiment_end = time.perf_counter()
#     average_latency = sum(latencies)/len(latencies)
#     print("Average latency:", average_latency)
#     print("Minmum latency:", min(latencies))
#     print("Maximum latency:", max(latencies))

#     elapsed = experiment_end - experiment_start
#     throughput = NUM_CLIENTS / elapsed
#     print("Throughput =", throughput)


# # Store latencies for one experiment
# latencies = []
# latency_lock = threading.Lock()




# def run_experiment(NUM_CLIENTS):

#     global latencies
#     latencies = []

#     threads = []

#     experiment_start = time.perf_counter()

#     for i in range(NUM_CLIENTS):
#         t = threading.Thread(target=worker, args=(i,))
#         t.start()
#         threads.append(t)

#     for t in threads:
#         t.join()

#     experiment_end = time.perf_counter()

#     elapsed = experiment_end - experiment_start
#     throughput = NUM_CLIENTS / elapsed

#     print("=" * 50)
#     print(f"Concurrent Clients : {NUM_CLIENTS}")
#     print(f"Average Latency    : {sum(latencies)/len(latencies):.6f} s")
#     print(f"Minimum Latency    : {min(latencies):.6f} s")
#     print(f"Maximum Latency    : {max(latencies):.6f} s")
#     print(f"Total Time         : {elapsed:.6f} s")
#     print(f"Throughput         : {throughput:.2f} auth/sec")


# if __name__ == "__main__":

#     client_numbers = [10, 20, 30, 40] 
#     [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200]

#     for n in client_numbers:
#         run_experiment(n)
    
#     results = []

# for n in [10, 20, 30, 40]:
# # [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200]:
#     avg, mn, mx, throughput = run_experiment(n)

#     results.append([
#         n,
#         avg,
#         mn,
#         mx,
#         throughput
#     ])

# with open("results.csv", "w", newline="") as f:
#     writer = csv.writer(f)

#     writer.writerow([
#         "Clients",
#         "AverageLatency",
#         "MinimumLatency",
#         "MaximumLatency",
#         "Throughput"
#     ])

#     writer.writerows(results)

def run_experiment(NUM_CLIENTS):

    latencies = []
    latency_lock = threading.Lock()

    threads = []

    experiment_start = time.perf_counter()

    for i in range(NUM_CLIENTS):

        t = threading.Thread(
            target=worker,
            args=(i, latencies, latency_lock)
        )

        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    experiment_end = time.perf_counter()

    elapsed = experiment_end - experiment_start
    throughput = NUM_CLIENTS / elapsed

    avg_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)

    print("=" * 50)
    print(f"Concurrent Clients : {NUM_CLIENTS}")
    print(f"Average Latency    : {avg_latency:.6f} s")
    print(f"Minimum Latency    : {min_latency:.6f} s")
    print(f"Maximum Latency    : {max_latency:.6f} s")
    print(f"Total Time         : {elapsed:.6f} s")
    print(f"Throughput         : {throughput:.2f} auth/sec")

    return {
        "Concurrent Clients": NUM_CLIENTS,
        "Average Latency (s)": avg_latency,
        "Minimum Latency (s)": min_latency,
        "Maximum Latency (s)": max_latency,
        "Experiment Time (s)": elapsed,
        "Throughput (auth/sec)": throughput
    }

def worker(clientID, latencies, latency_lock):

    start = time.perf_counter()

    AVA_program()

    end = time.perf_counter()

    latency = end - start

    with latency_lock:
        latencies.append(latency)


if __name__ == "__main__":

    # client_numbers = [10, 20, 30, 40]
    # Or:
    client_numbers = list(range(10, 31, 10))

    results = []

    for n in client_numbers:
        result = run_experiment(n)
        results.append(result)

    csv_filename = "authentication_benchmark.csv"

    with open(csv_filename, "w", newline="") as csvfile:

        fieldnames = results[0].keys()

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to '{csv_filename}'")