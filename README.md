This code is a electronic voting system written by c++. Some linux system calls are used to protect the user's password from being revealed. The blind signature functions use RSA and SHA encryption/decryption from OpenSSL library. The paillier encryption/decryption library is partly from https://github.com/GerardGarcia/paillier-c I made several changes to the library making it usable for this project.

Function prototypes as well as the implementation of bulletin board, election board and counting authority are all at the beginning of voting_system.cpp  

Please install the following packages before compile:

sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install openssl libssl-dev

Please use the following command to compile the code:

make voting_system

Please use the following command to run the code:

make run

The code will firstly generate a 2048bit of RSA key-pair using the openssl command. Then it will read votes' information and candidates' information from voters.txt and candidates.txt before starting the voting system.

