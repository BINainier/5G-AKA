# -*- coding:utf-8 -*-
import threading
import time
import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random
import time

#reveive SUCI, decrypt and generate SUPI
def SUPI(suci):#suci length:21 supi length:
    mcc = suci[1:4]#3
    mnc = suci[4:6]#2
    msin = suci[11:]#10
    supi = mcc+mnc+msin
    return supi#15

def Generate_rand():
    rand=''
    for num in range(0,32):
        rand=rand+str(random.choice('0123456789abcdef'))
    return  rand

def KDF_ausf(key, P0, L0, P1, L1):
    #generate CK', IK'
    appsecret = key
    s = '6A'+P0+L0+P1+L1
    tmp = hmac.new(appsecret, s, digestmod=sha256).hexdigest()
    ck_new = tmp[:32]
    ik_new = tmp[32:]
    key_new = ck_new+ik_new
    K_ausf = hmac.new(key_new, s, digestmod=sha256).hexdigest()
    return K_ausf

def KDF_xres(key, P0, L0, P1, L1,P2,L2):
    #generate Xres_star
    appsecret = key
    s = '6B' + P0 + L0 + P1 + L1+ P2 + L2
    # print 's:' +s
    tmp=hmac.new(appsecret, s, digestmod=sha256).hexdigest()
    xres_star=tmp[32:]
    return xres_star

def SentTo_AUSF(data,host,port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    data = '01' + data
    client.send(data)
    client.close()

def receive_from_AUSF(port):
    HOST = ''
    PORT = port
    ADDR = (HOST, PORT)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(5)
    while True:
        print 'Waiting for connection with AUSF...'
        tcpCliSock,addr = server.accept()
        data = tcpCliSock.recv(1024)
        tcpCliSock.close()
        server.close()
        return data

def Init():
    ki = '000000012449900000000010123456d8'
    #rand = '9fddc72092c6ad036b6e464789315b78'
    rand=Generate_rand()
    sqn = '1234567888d8'
    amf = '8d00'
    op = 'cda0c2852846d8eb63a387051cdd1fa5'
    return ki,rand,sqn,amf,op

def main():
    fp = open('udm.log','a+')
    data=receive_from_AUSF(9999)
    print 'Get SUCI and SN name from AUSF.\n'
    fp.write(time.ctime()+'        Get SUCI and SN name from AUSF.\n')
    data=str(data)
    suci = data[:21]
    supi = SUPI(suci)
    ki, rand, sqn, amf, op = Init()
    #test

    #before inter milenage
    #unhexlify
    ki = binascii.unhexlify(ki)
    op = binascii.unhexlify(op)
    rand = binascii.unhexlify(rand)
    sqn = binascii.unhexlify(sqn)
    amf = binascii.unhexlify(amf)

    opc = milenage.MilenageGenOpc(ki, op)
    xres, ck, ik, AUTN, ak = milenage.Milenage(ki, opc, rand, sqn, amf)


    key = ck + ik
    # P0 = 'xiiian'  # accept from AUSF
    # L0 = len(P0)  # accept from AUSF
    P0 = str(data)[21:]
    L0 = binascii.hexlify(str(len(P0)))

    P1 = binascii.hexlify(milenage.LogicalXOR(sqn, ak))
    L1 = binascii.hexlify(str(len(P1)))
    K_ausf = KDF_ausf(key, P0, L0, P1, L1)

    #generate xres*
    P1 = binascii.hexlify(rand)
    L1 = binascii.hexlify(str(len(rand)))
    P2 = binascii.hexlify(xres)
    L2 = binascii.hexlify(str(len(xres)))
    AUTN = binascii.hexlify(AUTN)
    xres_star = KDF_xres(key, P0, L0, P1, L1, P2, L2)

    rand=binascii.hexlify(rand)
    HE_AV = rand + AUTN + xres_star + K_ausf

    # # rand=32 AUTN=32 XRES_star=32 K_ausf=64
    # print HE_AV#160

    host3='127.0.0.1'#Channel Server IP
    port3=10000 #Channel Server Port
    message=str(HE_AV)+str(supi)
    SentTo_AUSF(message,host3,port3)
    print 'Send 5G HE AV and SUPI to AUSF.\n'
    fp.write(time.ctime()+'        Send 5G HE AV and SUPI to AUSF.\n')
    fp.close()


    
if __name__ == "__main__":
    main()
