#resolve message from AUSF,UE,SEAF,UDM
# AUSF Server Port 6001 Flag 01
 # SEAF Server Port 7001 Flag 02
# UE Server Port 9998 Flag 03
 # UDM ServerPort 9999 Flag 04
 # Channel ServerPort 10000

import socket
def SentTo_AUSF(data):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host='127.0.0.1'
    port= 6001
    client.connect((host, port))
    client.send(data)
    client.close()

def SentTo_UE(data):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 9998
    client.connect((host, port))
    client.send(data)
    client.close()

def SentTo_UDM(data):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 9999
    client.connect((host, port))
    client.send(data)
    client.close()

def SentTo_SEAF(data):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 7001
    client.connect((host, port))
    client.send(data)
    client.close()

def Resolve(data):
    Flag=data[:2]
    message=data[2:]
    return Flag,message

def main():
    host = ''  # LOCAL Server IP
    port = 10000# LOCAL Server port
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print('Waiting for connection...')
    while True:
        sock, addr = server.accept()
        data = sock.recv(1024)
        Flag,message=Resolve(data)
        if Flag=='01':
            SentTo_AUSF(message)
        elif Flag=='02':
            SentTo_SEAF(message)
        elif Flag=='03':
            SentTo_UE(message)
        elif Flag=='04':
            SentTo_UDM(message)
if __name__ == "__main__":
    main()




