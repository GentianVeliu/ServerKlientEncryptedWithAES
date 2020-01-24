# Klienti

import base64
import sys, socket, select
from Crypto.Cipher import AES
import os
import hashlib
import signal

os.system("clear")

def sigint_handler(signum, frame):
    print '\n user interrupt ! shutting down'
    print "[info] shutting down KLIENTI \n\n"
    sys.exit()	
    
#signal.signal() eshte funksion qe iu lejon disa handlers te ekzekutohen kur nje sinjal pranohet
signal.signal(signal.SIGINT, sigint_handler)

#hashlib.algoritmi e bene hashimin me algoritmin perkates 
#hexdigest() e kthen ne hex stringun e hash-it, ne rastin kur nevojitet vargu i bitave perdoret edhe digest
#sha512 llogarit hashin  64 bitshe, md5 prodhon hashin 128 bitsh
def hasher(key):
	hash_object = hashlib.sha512(key)
	hexd = hash_object.hexdigest()
	hash_object = hashlib.md5(hexd)
	hex_dig = hash_object.hexdigest()
	return hex_dig

#funksioni lambda : lambda argument: expression
#madhesia e bllokut qe enkriptohet ne AES duhet te jete 16, 24 ose 32 
#karakteri qe perdoret per padding with per nje bllok cipher siq eshte AES, vlera qe enkriptohet
#duhet te jete shumfishi i gjatesise se BLOCK_SIZE. Ky karakter perdoret per me u siguru qe vlera  
#jone eshte gjithmone shumfish i BLOCK_SIZE
def encrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
#one-liner to sufficiently pad the text to be encrypted(nje rresht qe mjaftueshem te mbushet teksti qe do te enkriptohet)
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
#one-liners to encrypt/encode and decrypt/decode a string
#encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(secret)
	encoded = EncodeAES(cipher, data)
	return encoded
#rstrip metoda  fshin hapsirat ne fund te stringut
def decrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new(secret)
	decoded = DecodeAES(cipher, data)
	return decoded

#funksioni len(sys.argv) numron numrin e argumenteve
#sys.argv[1] eshte argumenti i pare qe ju e jepni ne program
def chat_client():
    if(len(sys.argv) < 5) :
        print 'Usage : python klienti.py <hostname> <port> <password> <username>'
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])
    key = sys.argv[3]
    key = hasher(key)	
    uname = sys.argv[4]
    
#socket.AF_INET-family, socket.SOCK_STREAM-tipi-nenkupton qe eshte lidhje TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)


    try :
        s.connect((host, port))

    except :
        print "\033[91m"+'Unable to connect'+"\033[0m"
        sys.exit()

    print "U lidh, tani mund te dergoni mesazhe"
    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()

    while 1:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            if sock == s:

                data = sock.recv(4096)

                if not data :
                    print "\033[91m"+"\nDisconnected from chat server"+"\033[0m"
                    sys.exit()
                else :
                    data = decrypt(key,data)
                    sys.stdout.write(data)
                    sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()
#sys.stdout eshte i ngjajshem me print, 
#cfaredo objekti eshte i pranueshem perderisa ka metoden write te shoqeruar me string.
#sys.stdout.flush pushes out all the data that has been buffered to that point to a file object. 
            else :

                msg = sys.stdin.readline()
                msg = '[ '+ uname +': ] '+msg
                msg = encrypt(key,msg)
                s.send(msg)
                sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()

if __name__ == "__main__":

    sys.exit(chat_client())
