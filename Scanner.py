import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", resp)
resp_dict = {'1': ['-v -sS', 'tcp'], '2': ['-v -sU', 'udp'], '3': ['-v -sS -sV -sC -A -O', 'tcp']}

if resp not in resp_dict.keys():
    print("Enter a valid option")
else:
    print("nmap version:", scanner.nmap_version())
    scanner.scan(ip_addr, "1-1024", resp_dict[resp][0])
    if ip_addr in scanner.all_hosts():
        print("Scanner Status:", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        protocol = resp_dict[resp][1]
        open_ports = scanner[ip_addr][protocol].keys()
        print("Open Ports:", ", ".join(open_ports))
    else:
        print("Host is not responding or doesn't exist")





