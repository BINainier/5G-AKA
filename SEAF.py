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

def SentTo_UE(data,host,port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'send RAND and ANTN to UE '
    client.send(data)

def SentTo_AUSF(data,host,port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(data)

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


def main():
    host = ''  # LOCAL Server IP
    host2 = '127.0.0.1'  # AUSF Server IP
    host3 = '127.0.0.1'  # UE Server IP
    port = 7001  # LOCAL Server Port
    port2 = 6001  # AUSF Server Port
    port3 = 9998  # UE ServerPort
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print('Waiting for connection...')
    print('等待与UE 和 AUSF连接')
    # listen to port 7001
    while True:
        while True:
            sock, addr = server.accept()
            print 'got connected from', addr
            data = sock.recv(1024)
            length = len(data)
            ##supi
            if length < 32:
                print 'get SUCI and snName from UE:'
                print data
                print 'send SUCI and snName to AUSF'
                SentTo_AUSF(data, host2, port2)

            elif length >= 160:
                print 'get 5gAV and SUPI from AUSF'
                AV, supi = AUSF_resolve(data)
                global hxres_star, K_seaf, rand  # save these three parameters
                rand, autn, hxres_star, K_seaf = AV_resolve(AV)
                print 'hxres_star:'+hxres_star
                message = rand + autn
                message=str(message)
                SentTo_UE(message, host3, port3)
                print 'send rand and autn to ue'

            elif length == 32:
                print 'get res* from UE'
                res_star = data

                hres_star = KDF_hres_star(rand, res_star)
                print 'hres* is'
                print hres_star
                # check
                if str(hres_star) == str(hxres_star):
                    print 'SEAF Authentication successful'
                    SentTo_AUSF(res_star, host2, port2)
                else:
                    print 'SEAF Authentication fail'

            elif length == 48:
                print 'get auts from UE'
                print 'Authentication failed'



if __name__ == "__main__":
    main()