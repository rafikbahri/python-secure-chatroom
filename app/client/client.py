import base64
import sys, socket, select
from Crypto.Cipher import AES
import os
import hashlib
import signal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import NoEncryption
import time
import getpass
from cryptography.hazmat.primitives.asymmetric import padding
BUFFER_SIZE = 8192
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

os.system("clear")
print ("""
    ----------------------------
        CLIENT STARTING...                 
    ----------------------------
""")

def sigint_handler(signum, frame):
    print ('\n User disconnected !!')
    print ("[info] shutting down Chat \n\n")
    sys.exit()  
    

signal.signal(signal.SIGINT, sigint_handler)

def create_csr(country , state , locality , org , cn , key) :     
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])).add_extension(
        x509.BasicConstraints(ca = False , path_length = None ) ,
        critical=True,
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    # Write our CSR out to disk.
    with open("clientcsr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def genkey() :      
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Write our key to disk for safe keeping
    with open("clientkey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm= NoEncryption(),
        ))
    return key 

def encrypt(public_key,msg):
    ciphertext = public_key.encrypt(
    msg,
    padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
    )
    )
    return ciphertext

def decrypt (public_key,msg):
    data = public_key.decrypt(
    msg,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return data

def send_file(pref , file) :
    f = open(file, 'rb') 

    l = f.read(BUFFER_SIZE)
    s.sendall(pref  + l)
    s.recv(1)
    f.close()

def send_msg(msg) : 
    data = str(msg)
    s.sendall(data)
    s.recv(1)


def recv_msg( ) : 
    data = s.recv(8192)
    s.sendall('1')
    return data


def rcv_file(file) :
    filename=str(file)
    with open(filename,'wb') as f : 
        data = s.recv(BUFFER_SIZE)
        f.write(data)
        f.close()
    s.sendall('1')


def register(ind,msg,key) :
    login = raw_input('login : ')
    password = getpass.getpass()
    email = raw_input('email : ')
    carte = raw_input('NCarte: ')

    create_csr(u"at",u"at",u"at",u"at",u"at",key)
    send_file(str(ind)+msg , 'clientcsr.pem') 
    rcv_file("certificate.pem")
    rcv_file("ca.pem")  
    print('registration complete') 
    send_msg(login)
    send_msg(password)
    send_msg(email)
    send_msg(carte)
    answer = recv_msg()
    print answer



def recv_available_clients():
    msg =  recv_msg()
    while msg != 'abc' :
      print msg
      msg = recv_msg()

def auth(ind) : 
    send_msg(str(ind) + 'aut')
    print 'time to authenticate : \n'
    login = raw_input('login : ')
    password = getpass.getpass()
    send_msg(login)
    send_msg(password)
    answer = recv_msg()
    if answer == 'done' :
        print 'authentification complete' 
        print '\navailable people to chat with : \n'
        recv_available_clients()
    else :
        print 'error , bad credentials'
        auth(ind)


def chat_client():
    if(len(sys.argv) < 5) :
        print ('Run : python client.py <hostname|ip_address> <port> <password> <nick_name>')
        sys.exit()
    key = genkey()
    host = sys.argv[1]
    port = int(sys.argv[2]) 
    uname = sys.argv[4]
    ind = 0 
    newuser = False 
    s.settimeout(2)
    reciever = 'none'

    try :
        s.connect((host, port))
        ind = recv_msg()

        print ind 
    except :
        print ("\033[91m"+'Unable to connect, Server is unavailable'+"\033[0m")
        sys.exit()

    print ("Connected to the chat server. You can start sending messages.")
    

    if (not os.path.isfile('certificate.pem') ) : 
        print'this is a new user , you should register'

        register(ind,'csr',key)
    auth(ind)
    pem_ca_cert = open('ca.pem','rb').read()
    
    ca_cert = x509.load_pem_x509_certificate(pem_ca_cert, default_backend())
    ca_key =  ca_cert.public_key()    


    pem_ca_key = open('clientkey.pem' , 'rb').read()
    my_key = serialization.load_pem_private_key(pem_ca_key, password = None,backend = default_backend()) 




    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()
    while 1:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            if sock == s:

                data = recv_msg()
                if not data :
                    print ("\033[91m"+"\nServer shutdown !!"+"\033[0m")
                    sys.exit()
                elif data[:7] == 'nouveau':
                    sys.stdout.write(data)
                else : 
                    data = decrypt(my_key,data)
                    sys.stdout.write(data)
                    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()

            else :

                msg = sys.stdin.readline()
                if reciever == 'none' : 
                    reciever = raw_input('choose reciever : ')
                send_msg(str(ind)+'msg')
                send_msg(reciever)
                msg = encrypt(ca_key,msg)
                send_msg(msg)


                
                sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()

if __name__ == "__main__":

    sys.exit(chat_client())

