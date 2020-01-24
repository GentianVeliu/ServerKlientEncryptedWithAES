#serveri
#moduli Configparser ne python perdoret per te punuar me fajllat e konfigurimit
import ConfigParser
#moduli base64 siguron funksione per te koduar te dhenat binare ne formatin e koduar base64
#dhe ti deshifroje kodimet e tilla perseri ne te dhena binare.
import base64
import sys, socket, select
from Crypto.Cipher import AES
import hashlib
import os
import signal

#Execute the command (a string) in a subshell.
os.system("clear")

def sigint_handler(signum, frame):
    print '\n user interrupt ! shutting down'
    print "[info] shutting down Klienti \n\n"
    sys.exit()	
    #sys - ky modul siguron qasje ne disa variabla/metoda te perdorura ose te mirembajtura nga interpreteri
    #psh: ne rastin tone e kemi perdorur metoden exit().  
  
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
    
#Configuration file dmth jane fajlla qe perdoren per te konfiguruar parametra
#per programe kompjuterike, perdoren per aplikacionet e perdoruesve, proceset e serverit
#dhe cilesimet e sistemit operativ.
#Klasa ConfigParser e permban disa metoda te nderfaqes RawConfigParser
config = ConfigParser.RawConfigParser()   
config.read(r'klienti.conf')
#disa metoda jane : get, set, write, read, add_section, return 

#config.get i merr vlerat e HOST, PORT, PASSWORD-IT, VIEW 
#edhe i vendos tek variablat perkatese
HOST = config.get('config', 'HOST')
PORT = int(config.get('config', 'PORT'))
PASSWORD = config.get('config', 'PASSWORD')
VIEW = str(config.get('config', 'VIEW'))
key = hasher(PASSWORD)
SOCKET_LIST = []
RECV_BUFFER = 4096


def chat_server():

    #soketi eshte menyre per tu lidhur severi me klienti
	#socket.AF_INET tregon se soketi ndegjon ne adresen e ipV4
	#SOCK_STREAM nënkupton protokollin TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Një program aplikacioni mund të përdorë setockopt () për të ndarë
    #hapësirën ,kontrollin e afateve kohore, ose lejimin e transmetimeve
    # të të dhënave te serverit.
	#SOL_SOCKET është vetë shtresa e soketave.
	#SO_REUSEADDR - Për bazat AF_INET kjo do të thotë që një soket mund të
    #lidhet, përveç kur ekziston një soketdëgjimi aktiv e lidhur në adresë.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #tregon se ku duhet lidhur soketi ne cilin host dhe cilin port
    server_socket.bind((HOST, PORT))
    #lejohen deri ne 10 klienta per tu lidhur ne server
    server_socket.listen(10)
    #shtoimi i serverit soketit

    SOCKET_LIST.append(server_socket)

    print "Serveri filloi ne portin " + str(PORT)

    while 1:
    # get the list sockets which are ready to be read through select
    # 4th arg, time_out  = 0 : poll and never block

        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)

        for sock in ready_to_read:

            if sock == server_socket:
                #sockfd eshte ndegjimi i pershkrimit te socketit.
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
                print "user-i (%s, %s) u lidh" % addr
                #broadcast ka domethenien e radhes(si psh radha e operacioneve aritmetike ne matematike)
                broadcast(server_socket, sockfd, encrypt(key,"[%s:%s] u kyq ne bisede\n" % addr))

            else:
                try:
                    #arritja ne bufer e dates
                    data = sock.recv(RECV_BUFFER)
                    #dektiptimi i fjaleve
                    data = decrypt(key,data)
                    if data:
                        #enkriptimi i qelesit
                        broadcast(server_socket, sock,encrypt(key,"\r" + data))
                        if VIEW == '1':
                          print data
                    else:

                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)

                        broadcast(server_socket, sock,encrypt(key,"user (%s, %s) eshte offline\n" % addr))

                except:
                    broadcast(server_socket, sock, "user (%s, %s) eshte offline\n" % addr)
                    continue

    server_socket.close()
#metoda broadcast per dergimin e te dhenave kur soketat jane te ndryshem
def broadcast (server_socket, sock, message):
    for socket in SOCKET_LIST:

        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :

                socket.close()

                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)
#Nëse interpretuesi i pythonit po e ekzekuton atë modul (skedarin burimor) si programin kryesor,
# ai vendos ndryshoren e veçantë __name__ që të ketë një vlerë "__main__". 
#Nëse kjo skedar po importohet nga një modul tjetër, __name__ do të vendoset në emrin e modulit.
#perdoret per te ekzekututar kodin vetem nese fajlli eshte bere run drejtperdrejt, dhe jo i importuar.
if __name__ == "__main__":

    sys.exit(chat_server())
