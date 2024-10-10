import socket
import nmap
import app.models.Tools as Tools
import dns.resolver
from app.models.Certificat import Certificat
from app.models.Port import Port
from app.models.Email import Email

class Dns:
    def __init__(self, dns:str, ip:str=""):
        self.dns = dns
        self.ip = ip
        self.owner:str = ""
        self.location:str = ""
        self.os:str = ""
        self.scanner = nmap.PortScanner()
        self.ports:list[Port] = []
        self.records = []
    
    def findIpAddress(self)->str:
        self.ip = socket.gethostbyname(self.dns)
    
    def scan(self):
        print("Start Scanning Ports...")

        options = "-sS -sV -O -A"
        self.scanner.scan(self.dns, arguments=options)
        
        print("Finished Ports Scan")
    
    def findPorts(self) :
        ports_info = Tools.csvTodict(self.scanner.csv())

        for port_info in ports_info:
            if(port_info["hostname_type"] == "user" and port_info["state"] == "open" ):    
                self.ports.append(Port(port_info))
        
    def findCveForEachPorts(self):
        for port in self.ports:
            port.findCves()
        return
    
    def findOS(self):
        if self.ip in self.scanner.all_hosts():
            host = self.scanner[self.ip]
            if "osmatch" in host:
                if len(host["osmatch"]) > 0:
                    self.os = host["osmatch"][0]["name"]
                    return
        self.os = "Not Found"
    
    def findRecords(self):
        records_types = [
            "A",             # Address Record (IPv4)
            "AAAA",          # IPv6 Address Record
            "CNAME",         # Canonical Name Record
            "MX",            # Mail Exchange Record
            "NS",            # Name Server Record
            "PTR",           # Pointer Record
            "TXT",           # Text Record
            "SOA",           # Start of Authority Record
            "SRV",           # Service Record
            "DNSKEY",        # DNS Key Record
            "DS",            # Delegation Signer Record
            "NSEC",          # Next Secure Record
            "NSEC3",         # Next Secure Version 3 Record
            "TLSA",          # TLSA Certificate Association Record
            "CAA",           # Certification Authority Authorization
            "HINFO",         # Host Information Record
            "RP",            # Responsible Person Record
            "SSHFP",         # SSH Public Key Fingerprint Record
            "SPF"            # Sender Policy Framework
        ]

        for record_type in records_types:
            try:
                answers = dns.resolver.resolve(self.dns, record_type)
                if answers:
                    print(f"Found {record_type} record for {self.dns}:")
                    self.records.append(record_type)
                    for rdata in answers:
                        print(rdata.to_text())
                else:
                    print(f"No {record_type} record found for {self.dns}")
            except dns.resolver.NoAnswer:
                print(f"No {record_type} record found for {self.dns}")
            except dns.resolver.NXDOMAIN:
                print(f"Domain {self.dns} does not exist")

        return

    
    
    def findCertificat(self):
        return
    
    def getIp(self):
        return self.ip
    
    def toStringGeneralInfo(self) -> str:
        return self.dns +" | "+ str(self.ip) +" | "+ str(self.os) +" | "+ str(self.owner) +" | "+ str(self.location) + "\n"
    
    def toStringScanInfo(self) -> str:
        string = self.toStringGeneralInfo()
        for port in self.ports:
            string += port.toString()
        return string

    def setOwner(self, owner):
        self.owner = owner
    
    def setLocation(self, location):
        self.location = location
    
    def to_dict(self):
        return self.__dict__
        

