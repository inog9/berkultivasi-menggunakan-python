import subprocess
import socket
import xml.etree.ElementTree as ET

def run_nmap(target,ports):
    xml_out = "temp.xml"
    command = ["nmap", "-Pn", "-sS", "-P", ports, target, xml_out]
    return xml_out

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    report = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            state = port.find("state").get("state")
            service = port.find("state").get("name", "tidaktahu")
            report.append((ip,port_id,state,service))
    return report

def quick_socket_scan(target, ports):
    found = []
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((target,port)) == 0:
            found.append(port)
        s.close()
    return found

#menjalankan reconnaisance full
host = "nama domainnya . xyz"
nmap_result = run_nmap(host,"22,80,443")
parse_data = parse_nmap(nmap_result)
print("[+] Nmap XML Parsed:")
for row in parse_data:
    print(row)


print("[+] Socket scan result:", quick_socket_scan(host, [22,80,443]))

