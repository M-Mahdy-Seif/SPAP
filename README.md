# CPMAVE
This is a python implementation of our protocol SPAP: a Secure and Privacy-Aware Protocol designed for avatar-based interactions within metaverse environments. 

Our implementation consists of three parts.

## The Cryptographic Overhead Timing
A Python program to calculate the cryptographic overhead time, which are required in our comparison with other protocols, such as the Hash function, Modular Inverse, Pairing, Scalar Multiplication, Point Addition, Modular EXponentation, Random Scalar generation. The measurements were reported based on the performance on a Raspberry Pi 5 with a 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU.

### Running on The Raspberry Pi 5
install the requirements:
```
pip install -r requirements.txt
```

Run the cryptographic primitives on the Raspberry Pi 5. `

## The Protocol Implementation
A Python implementation of the protocol where the registration for two metaverse user U_m and U_w. Afterwards, the protocol is executed between the metaverse avatars AVa_m and Ava_n for the mutual authentication and between the Ava_m and the custodian entity for obtaining an valid accountability token.

### Running the protocol on the Laptop:
```
cd "SPAPImplementation"
python3 02_SPAP.py
```

## The Socket Programming
A Python socket programming implementation of SPAP to simulate the flow of our protocol messages between the avatars Ava_m and Ava_n in a real-time experiment and to measure the end-to-end latency. 
The Raspberry Pi $5$ with a 2.4 GHz quad-core 64-bit Arm Cortex-A76 CPU represents the first avatar while the macBook Pro equipped with a 6-core Intel Core i7 processor and 16
GB of DDR4 RAM., acts as the second avatar.
### Running the Socket Programming
Start the Ava_m. The ECA will listen on port 5000:
```
cd "Socket Programming"
python3 03_Ava_n.py
```
Start the Ava_n. The gateway will listen on port 5001. 
```
cd "Socket Programming"
python3 04_Ava_n_server.py
```
 
