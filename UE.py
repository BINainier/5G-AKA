# -*- coding:utf-8 -*-
#UE receive rand and AUTN from SEAF, check freshness by AUTN
#Then ues res+ik+ck generate res*
#Send res* to SEAF


import binascii
import hmac
from hashlib import sha256
import socket
import milenage
import random
import time

def Generate_IMSI():
    imsi = '46000'
    for num in range(0,10):
        imsi=imsi + str(random.choice('0123456789'))
    return imsi

#generate SUCI

def Generate_SUCI(imsi):
    mcc = imsi[:3]
    mnc = imsi[3:5]
    msin = imsi[5:]
    suci = '0'+mcc+mnc+'678'+'0'+'0'+msin #21
    return suci

#send SUCI to seaf
def Send_To_SEAF(host, port):
    imsi = Generate_IMSI()
    suci = Generate_SUCI(imsi)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    suci=suci+sn_name
    data='02'+suci

    client.send(data)
    client.close()
def Send_res_star_To_SEAF(res_star, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'Access! Send res* to SEAF\n'
    data='02'+res_star
    client.send(data)
    client.close()

def Send_auts_To_SEAF(auts, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'AUTS Fails!\n Send auts to SEAF'
    data='02'+auts

    client.send(data)
    client.close()

#reveive Auth-Req(rand, AUTN) from SEAF
def reveive_authreq_from_SEAF(port):
    HOST =''
    PORT = port
    ADDR = (HOST, PORT)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(5)
    while True:
        tcpCliSock, addr = server.accept()
        print 'Waiting for connection with SEAF...'
        print 'got connected from SEAF'
        data = tcpCliSock.recv(1024)

        print 'receive Auth-Req from SEAF\n'

        return data


#resolve AUTN
def AUTN_resolve(AUTN):

    sqn_ak = AUTN[:6]
    amf = AUTN[6:8]
    mac_a = AUTN[8:]
    return sqn_ak, amf, mac_a


#F-function in UE
def milenage_ue(rand, AUTN, ki, op):

    #F5*
    i= 0
    opc = milenage.MilenageGenOpc(ki, op)
    tmp1 = milenage.LogicalXOR(rand, opc)
    tmp2 = milenage.AESEncrypt(ki, tmp1)
    # tmp1 = milenage.LogicalXOR(tmp2, opc)
    #tmp1 = tmp1[:15] + chr(ord(tmp1[15]) ^ 1)
    ak_map = {}
    for i in range(16):
        ak_map[(i+4)%16] = milenage.__XOR__(tmp2[i], opc[i])
    ak_map[15] = milenage.__XOR__(ak_map[15], chr(8))
    tmp1 = ''.join(val for val in ak_map.values())
    tmp1 = milenage.AESEncrypt(ki, tmp1)
    ak_star = milenage.LogicalXOR(tmp1, opc)
    
    sqn_ak, amf, mac_a = AUTN_resolve(AUTN)
    res, ck, ik, ak = milenage.MilenageF2345(ki, opc, rand)
    sqn = milenage.LogicalXOR(sqn_ak, ak)
    xmac_a, xmac_s = milenage.MilenageF1(ki, opc, rand, sqn, amf)

    return sqn, res, ck, ik, ak, ak_star, xmac_a, xmac_s, mac_a

#generate res*
def KDF_res_star(ck, ik, P0, L0, rand, res):
    key = ck+ik
    P1 = binascii.hexlify(rand)

    L1 = binascii.hexlify(str(len(rand)))
    P2 = binascii.hexlify(res)
    L2 = binascii.hexlify(str(len(res)))
    s ='6B' + P0 + L0 + P1 + L1 + P2 + L2
    # print 's:' +s
    tmp=hmac.new(key, s, digestmod=sha256).hexdigest()
    res_star=tmp[32:]
    return res_star

#check MAC
def check_mac(xmac_a, mac_a):
    if xmac_a==mac_a:
        return 1
    else :
        return 0

#check sqn
def check_sqn(sqn):
    pass

#send res* to seaf


#generate auts
def generate_auts(sqn_ms, ak_star, xmac_s):
    tmp = milenage.LogicalXOR(sqn_ms, ak_star)
    auts = tmp+xmac_s
    auts=binascii.hexlify(auts)
    return auts

#send auts to seaf


def Init():
    ki = '000000012449900000000010123456d8'
    op = 'cda0c2852846d8eb63a387051cdd1fa5'
    global sn_name
    sn_name = 'xiiian'
    sqn_max = '100000000000000000000000'
    return ki, op, sn_name, sqn_max

def main():

    ki, op, sn_name, sqn_max = Init()
    fp = open('ue.log', 'a+')
    # localtime = str(time.asctime(time.localtime(time.time())))

    #send SUCI to SEAF
    host = '127.0.0.1'
    port = 10000#Channel port

    Send_To_SEAF(host,port)
    fp.write(time.asctime(time.localtime(time.time()))+'        Send SUCI to SEAF.\n')
    print 'UE:\n Send SUCI to SEAF.\n'

    #reveive Auth-Req from SEAF
    port2 = 9998#local port
    auth_req = reveive_authreq_from_SEAF(port2)
    fp.write(time.asctime(time.localtime(time.time()))+'        Receive Auth-Req from SEAF.\n')
    # auth_req=binascii.hexlify(auth_req)

    rand = auth_req[:32]

    autn = auth_req[32:]

    sqn_ak, amf, mac_a=AUTN_resolve(autn)


    ki = binascii.unhexlify(ki)
    op = binascii.unhexlify(op)
    rand = binascii.unhexlify(rand)
    autn=binascii.unhexlify(autn)
    sqn, res, ck, ik, ak, ak_star, xmac_a, xmac_s, mac_a = milenage_ue(rand, autn, ki, op)
    # print 'xmac_a:'+xmac_a
    # print 'mac_a:'+mac_a
    # print 'res:  '+res

    if check_mac(xmac_a, mac_a):
        P0 = sn_name
        L0 = binascii.hexlify(str(len(sn_name)))
        res_star = KDF_res_star(ck, ik, P0, L0, rand, res)
        # print 'res* : '+res_star

        Send_res_star_To_SEAF(res_star, host, port)
        fp.write(time.asctime(time.localtime(time.time()))+'        Access! Send res* to SEAF.\n')
    else:
        auts = generate_auts(sqn_max, ak_star, xmac_s)
        Send_auts_To_SEAF(auts, host, port)
        fp.write(time.asctime(time.localtime(time.time()))+'        AUTS Fails! Send auts to SEAF.\n')
    fp.close()



if __name__ == "__main__":
    main()