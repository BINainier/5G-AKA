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

def Generate_IMSI():
    imsi = '46000'
    for num in range(0,9):
        imsi=imsi + str(random.choice('0123456789'))
    return imsi

#generate SUCI

def Generate_SUCI(imsi):
    mcc = imsi[:3]
    mnc = imsi[3:5]
    msin = imsi[5:]
    suci = '0'+mcc+mnc+'678'+'0'+'0'+msin
    return suci

#send SUCI to seaf
def Send_To_SEAF(host, port):
    imsi = Generate_IMSI()
    suci = Generate_SUCI(imsi)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'SUCI IS :'
    print suci
    suci=suci+'xidian'
    print 'send SUCI to SEAF\n'
    client.send(suci)

#reveive Auth-Req(rand, AUTN) from SEAF
def reveive_authreq_from_SEAF(port):
    HOST =''
    PORT = port
    ADDR = (HOST, PORT)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(5)
    while True:
        print 'Waiting for connection...'
        tcpCliSock, addr = server.accept()
        print 'Waiting for connection with SEAF...'
        print 'got connected from ', addr
        data = tcpCliSock.recv(1024)

        print 'get data from SEAF:\n'

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
    tmp1 = milenage.LogicalXOR(tmp2, opc)
    #tmp1 = tmp1[:15] + chr(ord(tmp1[15]) ^ 1)
    tmp2 = tmp1[:15] + chr(ord(tmp1[15]) ^ 1)
    ak_map = {}
    for i in range(16):
        ak_map[(i+4)%16] = milenage.__XOR__(tmp2[i], opc[i])
    ak_map[15] = milenage.__XOR__(ak_map[15], chr(8))
    tmp1 = ''.join(val for val in ak_map.values())
    tmp1 = milenage.AESEncrypt(ki, tmp1)
    ak_star = milenage.LogicalXOR(tmp1, opc)
    
    sqn_ak, amf, mac_a = AUTN_resolve(AUTN)
    print 'ki:'
    print  ki
    print 'opc:'
    print opc
    print 'rand:'
    print rand
    res, ck, ik, ak = milenage.MilenageF2345(ki, opc, rand)
    sqn = milenage.LogicalXOR(sqn_ak, ak)
    xmac_a, xmac_s = milenage.MilenageF1(ki, opc, rand, sqn, amf)

    return sqn, res, ck, ik, ak, ak_star, xmac_a, xmac_s, mac_a

#generate res*
def KDF_res_star(ck, ik, P0, L0, rand, res):
    key = ck+ik
    P1 = binascii.hexlify(rand)

    L1 = str(len(rand))
    P2 = binascii.hexlify(res)
    L2 = str(len(res))
    s ='6B' + P0 + L0 + P1 + L1 + P2 + L2
    print 's:' +s
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
def Send_res_star_To_SEAF(res_star, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'send res* to SEAF\n'
    client.send(res_star)

#generate auts
def generate_auts(sqn_ms, ak_star, xmac_s):
    tmp = milenage.LogicalXOR(sqn_ms, ak_star)
    auts = tmp+xmac_s
    auts=binascii.hexlify(auts)
    return auts

#send auts to seaf
def Send_auts_To_SEAF(auts, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'send auts to SEAF\n'
    print
    client.send(auts)

def Init():
    ki = '000000012449900000000010123456d8'
    op = 'cda0c2852846d8eb63a387051cdd1fa5'
    sn_name = 'xidian'
    sqn_max = '100000000000000000000000'
    return ki, op, sn_name, sqn_max

def main():

    ki, op, sn_name, sqn_max = Init()
    P0 = sn_name
    L0 = str(len(P0))

    #send SUCI to SEAF
    host = '127.0.0.1'
    port = 7001#Seaf port
    Send_To_SEAF(host,port)


    #reveive Auth-Req from SEAF
    port2 = 9998#local port
    auth_req = reveive_authreq_from_SEAF(port2)
    print auth_req
    # auth_req=binascii.hexlify(auth_req)

    rand = auth_req[:32]
    print 'rand is:'
    print rand
    autn = auth_req[32:]
    print 'autn is:'
    print autn
    sqn_ak, amf, mac_a=AUTN_resolve(autn)
    print 'amf is:'
    print binascii.hexlify(amf)
    print sqn_ak, amf, mac_a

    ki = binascii.unhexlify(ki)
    op = binascii.unhexlify(op)
    rand = binascii.unhexlify(rand)
    autn=binascii.unhexlify(autn)
    sqn, res, ck, ik, ak, ak_star, xmac_a, xmac_s, mac_a = milenage_ue(rand, autn, ki, op)
    print 'ck,ik:'
    print ck,ik
    print 'res:'
    res=binascii.hexlify(res)
    print str(res)

   # if check_mac(xmac_a, mac_a):
    P0 = 'xidian'
    L0 = str(len(sn_name))
    res_star = KDF_res_star(ck, ik, P0, L0, rand, res)
    print 'res* is'
    print res_star
    Send_res_star_To_SEAF(res_star, host, port)

    #else:
     #   auts = generate_auts(sqn_max, ak_star, xmac_s)
      #  print 'auts is:'
       # print auts
        #Send_auts_To_SEAF(auts, host, port)



if __name__ == "__main__":
    main()