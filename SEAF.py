# -*- coding:utf-8 -*-
#SEAF receive 5G_AV from AUSF
#send rand, AUTN to UE
#receive res* from UE, generate hres*
#verificate hres* and hxres*


import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random
import threading


#generate hres*
def KDF_hres_star(rand, res_star):
    s = rand+res_star
    tmp = sha256()
    tmp.update(s)
    value = tmp.hexdigest()
    hres_star = value[32:]
    return hres_star

#generate K_amf
def KDF_Kamf(K_seaf, supi):
    P0 = supi
    L0 = str(len(supi))
    P1 = '0000'
    L1 = str(len(P1))
    s = '6D'+P0+L0+P1+L1
    K_amf = hmac.new(K_seaf, s, digestmod=sha256).hexdigest()
    return K_amf

def SentTo_UE(data):
    host2 = '127.0.0.1'
    port2 = 10000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host2, port2))
    data='03'+data
    client.send(data)
    client.close()

def SentTo_AUSF(data):
    host3 = '127.0.0.1'
    port3 = 10000
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host3, port3))
    data='01'+data
    client.send(data)
    client.close()

def AV_resolve(data):
    rand = data[:32]
    autn = data[32:64]
    hxres_star = data[64:96]
    K_seaf = data[96:]
    return rand,autn,hxres_star,K_seaf
#handle 5gAV and supi from AUSF
def AUSF_resolve(data):
    AV=data[:160]
    supi=data[160:]
    return AV,supi

def handle(sock,addr):
    global tic
    import time
    fp = open('seaf.log', 'a+')

    data = sock.recv(1024)
    length = len(data)
    # if lock.acquire(True):
    ##supi
    if length < 32 and data != 'successful from AUSF':
        # Timing begins

        tic = time.time()
        print 'Get SUCI and snName from UE.'
        fp.write(time.ctime() + '        Get SUCI and snName from UE.\n')
        print 'Send SUCI and snName to AUSF.\n'
        fp.write(time.ctime() + '        Send SUCI and snName to AUSF.\n')
        SentTo_AUSF(data)


    elif length >= 160:
        print 'Get 5gAV and SUPI from AUSF.'
        fp.write(time.ctime() + '        Get 5gAV and SUPI from AUSF.\n')
        AV, supi = AUSF_resolve(data)
        global hxres_star, K_seaf, rand  # save these three parameters
        rand, autn, hxres_star, K_seaf = AV_resolve(AV)
        # print 'hxres*:'+hxres_star
        message = rand + autn
        message = str(message)
        print 'Send RAND and AUTN to UE.\n'
        fp.write(time.ctime() + '        Send RAND and AUTN to UE.\n')
        SentTo_UE(message)


    elif length == 32:
        print 'Get res* from UE.'
        res_star = data

        hres_star = KDF_hres_star(rand, res_star)
        # print 'hres* :'+ hres_star
        # check
        if str(hres_star) == str(hxres_star):
            print 'SEAF Authentication is successful.\n'
            fp.write(time.ctime() + '        SEAF Authentication is successful.\n')

            SentTo_AUSF(res_star)
        else:
            print 'SEAF Authentication fails.\n'

            fp.write(time.ctime() + '        SEAF Authentication fails.\n')
            fp.close()
            # lock.release()

    elif length == 48:
        print 'Receive auts from UE; AKA fails.\n'

        fp.write(time.ctime() + '        Authentication fails!\n')
        fp.close()
        # lock.release()
    elif data == 'successful from AUSF':
        print 'Receive Authenticate Response from AUSF.\nAKA is successful!\n'

        fp.write(time.ctime() + '        Receive Authenticate Response from AUSF. AKA is successful!\n')
        fp.close()
        # timing ends
        global toc
        import time
        toc = time.time()
        time = toc - tic
        print 'Time consumption is %lf s' % time
        # lock.release()


def main():
    host = ''  # LOCAL Server IP

    port = 7001  # LOCAL Server Port

    # global lock
    # lock = threading.Lock()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print('SEAF:\nWaiting for connection with UE ...\n')

    # listen to port 7001
    while True:
        sock, addr = server.accept()
        threading.Thread(target=handle, args=(sock, addr)).start()
        # threading._start_new_thread(handle, sock)



if __name__ == "__main__":
    main()