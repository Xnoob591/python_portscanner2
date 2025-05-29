import nmap
import pyfiglet
import socket 

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        socket.error(ip)
        return False
       
    
#ip, port_range, mode are variables used here 
def run_scan(ip, mode, port_range="1-1024"):
    scanner = nmap.PortScanner()
    try:
        if mode == "1": #implementing service scan process
            print("you are running service scan\n")
            scanner.scan(ip, port_range,"-sV -A -T4") #theses are arguments in scan attribute of nmap module
            port_list = scanner[ip]['tcp'].keys()
            for proto in scanner[ip].all_protocols():
                ports = scanner[ip][proto].keys()
            for port in ports:
                print(f"Port: {port} State: {scanner[ip][proto][port]['state']} Service: {scanner[ip][proto][port]['name']}")
        elif mode == "2":  #for OS scan nmap -O -A used 
            print("you are running OS scan\n")
            scanner.scan(ip, port_range, "-O -A -T4")
            print("OS found here is-->>",scanner[ip]['osmatch'][0]['name']) #configure 
        elif mode == "3": #this scan only discover hosts no port scan running at all 
            scanner.scan(hosts=ip, arguments=' -sn')
            print(f"{ip} has host called {(scanner[ip]['hostnames'][0]['name'])}")#configure
        elif mode == "4": #this scan only running port scan without discovering hosts
            scanner.scan(ip, port_range, "-Pn -T4")
            port1 = (scanner[ip]['tcp'])
            for port in port1:
                print(f"Host opened ports are \n{port}")
        else:
            print("invalid ip please try again shortly")
            return
        if ip not in scanner.all_hosts():
            print("host seems down or blocked by a firewall")
        print(f"----Printed results for nmap scan ip {ip}-----")
        protocols = scanner[ip].all_protocols()#these code lines should be adjusted 36 37 38 39 40 41
        print("SCANNED HOST IS__",scanner[ip].state(), "__")
        

        
    except Exception as e:
        return
    except nmap.PortScannerError() as e:
        return
  
print(pyfiglet.figlet_format("CyBeRcHeF Scanner"))
print("<<---PORT SCANNER USING PYTHON--->>>")
ip = input("Enter your ip:  ")
if not validate_ip(ip):
    print("invalid ip address")
    exit() #exit or any command is not executede after return statements that y above validadte func exit() didnt work there
print(
    """what mode you want to run the scan:
    1-service scan
    2-os scan
    3-host discovery 
    4-port scan 
        
    """)
mode = input("Enter your choice: ")
port_range = input("Enter port range you want to run(Default:0-1024):: ") or "0-1024"

run_scan(ip,mode, port_range)



    
