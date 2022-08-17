import argparse
import re
import threading
import socket
import sys
import traceback
import paramiko

userSession = [""]
curr_user = ""
users = {}



class HoneypotSSH(paramiko.ServerInterface):

    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
            

    def get_allowed_auths(self, username):
        global curr_user 
        curr_user = username
        return "password"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL        
    
    def check_auth_password(self, username, password):
        global users
        if username in users.keys():
            users[username] = users[username]+1
        else:
          users[username] = 1     
        
        if  users[username] < 6:
           return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL   

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True



def Connect(client, addr):

    client_ip = addr[0]
    print('New connection is here from: {}'.format(client_ip))

    try:
        
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey(filename='server.key'))
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        server = HoneypotSSH(client_ip)
    
        try:
            transport.start_server(server=server)
            

        except paramiko.SSHException:
            raise Exception("SSH negotiation failed")
        chan = transport.accept(60)
        while chan is None:
            chan = transport.accept(60)
        if chan is None:
            print('NO CHANNEL =>'+client_ip)
            raise Exception("No channel")
        
        chan.settimeout(60)

        server.event.wait(60)
        if not server.event.is_set():
            raise Exception("No shell request")
     
        try:
            chan.send("==========Welcome to CS468 HoneyPot==========\r\n")
            run = True
            while run:
                chan.send(curr_user+"@honeypot:/$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    chan.send(transport)
                    command =command+ transport.decode("utf-8")
                
                chan.send("\r\n")
                command = command.rstrip()

                if command == "quit":
                    run = False

                else:
                    handle_cmd(command, chan)

        except Exception as err:
            print('Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass



def ServerLaunch(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening on port {} ...'.format(port))
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=Connect, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)



def handle_cmd(cmd, chan):

    response = ""
    if cmd.startswith("ls") or cmd.startswith(" ls"):
        if len(userSession)==0:
            response = "\r"
        else:    
            for i in range(len(userSession)):
                response = response+ " "+ userSession[i]
    elif cmd.startswith("echo") or cmd.startswith(" echo"):
        Splitcmd = cmd.split(' ')
        filename=[w for w in Splitcmd if w.endswith('.txt')]
        words = re.findall('"([^"]*)"', cmd)
        if not filename:
            response = "Unknown file extension"
        else: 
            userSession.append(filename[0])
            file = open(filename[0],"w")
            file.write(words[0])   
            response =  ""
    elif cmd.startswith("cat") or cmd.startswith(" cat"):
         Splitcmd = cmd.split(' ')
         filename=[w for w in Splitcmd if w.endswith('.txt')]
         if not filename:
            response = "Unknown file extension"
         else: 
            if filename[0] in userSession:
                file = open(filename[0],"r") 
                response = file.read()
            else:
                response = " File " + filename[0]+ " not found"    
    elif cmd.startswith("cp") or cmd.startswith(" cp"):
        Splitcmd = cmd.split(' ')
        filename=[w for w in Splitcmd if w.endswith('.txt')]
        if len(filename) != 2:
            response = "wrong number of arguments"
        elif not filename:
            response = "Unknown file extension"
        elif filename[0] not in userSession:
            response = " File " + filename[0]+ " not found"     
        
        else:
            file1 = open(filename[0],"r") 
            file2 = open(filename[1],"w")
            for line in file1:
                file2.write(line)
            userSession.append(filename[1])   
            response = ""                

    if response != '':
        response = response + "\r\n"
    chan.send(response)



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-p", default=22, type=int, action="store")
    args = parser.parse_args()
    ServerLaunch(args.port)
