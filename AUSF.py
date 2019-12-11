# -*- coding:utf-8 -*-
#
# AUSF receive 5G_HE_AV from UDM, generate K_seaf, HXRES* and replace them in 5G_HE_AV, turn 5G_HE_AV to 5G_AV


import binascii
import hmac
from hashlib import sha256
import socket
import time

def KDF_seaf(K_ausf, P0, L0):
    # generate K_seaf
    # P0 seiving net work name
    #P1 length of network name
    s ='6C'+P0+L0
    key = K_ausf
    K_seaf = hmac.new(key, s, digestmod=sha256).hexdigest()
    return K_seaf

def KDF_hxres_star(rand, xres_star):
    s =rand+xres_star
    tmp = sha256()
    tmp.update(s)
    value = tmp.hexdigest()
    hxres_star = value[32:]
    return hxres_star

def SEAF_resolve(data):
    suci=data[:21]
    snName=data[21:]
    return  suci,snName

def UDM_resolve(data):
    HE_AV=data[:160]
    supi=data[160:]
    return HE_AV,supi

def HE_AV_resolve(data):
    rand=data[:32]
    autn=data[32:64]
    xres_star=data[64:96]
    K_ausf=data[96:]
    return rand, autn, xres_star, K_ausf

def Generate_AV(rand,autn,hxres_star,K_seaf):
    AV=rand+autn+hxres_star+K_seaf
    #rand 32 autn 32 hxres_star32 K_seaf64
    return AV

def SentTo_UDM(data,host3,port3):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host3, port3))
    data='04'+data

    client.send(data)
    client.close()

def SentTo_SEAF(data,host2,port2):
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect((host2, port2))
    data='02'+data

    client2.send(data)
    client2.close()

def main():
    host = ''  #  LOCAL Server IP
    host2 = '127.0.0.1'  # Channel Server IP
    host3='127.0.0.1' # Channel Server IP
    port = 6001  # LOCAL Server Port

    port2=10000 #Channel Server Port

    port3 = 10000  # Channel Server Port
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    #listen to port 6001
    server.listen(5)
    print('AUSF:\nWaiting for connection with SEAF...\n')
    fp = open('ausf.log', 'a+')
    while True:
        sock, addr = server.accept()

        data = sock.recv(1024)
        length = len(data)
        if length < 32:
            # print 'accept suci and sn name from seaf'
            # print 'suci and sn name is:' + data
            suci, snName = SEAF_resolve(data)
            global P0
            P0 =  binascii.hexlify(snName)  # sn name
            global L0
            # sn name格式？ sn name的长度如何定义？
            L0 = str(len(snName))  # length of sn name
            print 'Send SUCI and SNname To UDM.\n'
            SentTo_UDM(data, host3, port3)  # send it to UDM
            fp.write(time.ctime()+'        Send SUCI and SNname To UDM.\n')

        elif length >= 160:
            print 'Receive 5g HE AV and SUPI from UDM.\n'
            fp.write(time.ctime()+'        Receive 5g HE AV and SUPI from UDM.\n')
            global xres_star
            xres_star = 0
            HE_AV, supi = UDM_resolve(data)
            rand, autn, xres_star, K_ausf = HE_AV_resolve(HE_AV)
            K_seaf = KDF_seaf(K_ausf, P0, L0)
            hxres_star = KDF_hxres_star(rand, xres_star)
            AV = Generate_AV(rand, autn, hxres_star, K_seaf)
            avlength = len(AV)
            # print 'AV length is:' + str(avlength)
            # print 'the result of Av is' + AV
            message = str(AV) + str(supi)
            SentTo_SEAF(message, host2, port2)
            print 'Send 5g AV and SUPI To SEAF.\n'
            fp.write(time.ctime()+'        Send 5g AV and SUPI To SEAF.\n')

        elif length == 32:
            # print 'accept Xres* from SEAF'
            # print data
            if str(data) == str(xres_star):  # 检验接收到的res*
                message = 'successful from AUSF'
                print 'Send Authenticate Response to SEAF.\n'
                SentTo_SEAF(message, host2, port2)
                fp.write(time.ctime()+'        Send Authenticate Response to SEAF.\n')
                fp.close()


if __name__ == "__main__":
    main()