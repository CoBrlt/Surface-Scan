#form file import class
import os
import urllib3
import json
import app.models.Tools as Tools
import socket
import ssl
from datetime import datetime
# import var
import requests
import time
import app.models.modules_Spiderfoot as modules_Spiderfoot
from app.models.Dns import Dns
from app.models.Dnsdumpster import Dnsdumpster
from app.models.Email import Email
from app.models.Certificat import Certificat
# Supprime le warning lié à la vérification du certficat
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def initSubdomains(dict_dump:dict):
    subdomains = []
    for subdomain in dict_dump:
        if subdomain["Type"] == "A":
            tmp = Dns(subdomain["Hostname"], subdomain["IP Address"])
            subdomains.append(tmp)
    return subdomains

def sortDomainsByIp(domains):
    domainsSorted = {}

    for dom in domains:
        sorted = False
        for ip in domainsSorted :
            if ip == dom.getIp():
                domainsSorted[ip].append(dom)
                sorted = True
                break
        if not sorted:
            domainsSorted[dom.getIp()] = [dom]

    return domainsSorted

def getOwnerAndLocationByIp(domainsSorted):
    for ip in domainsSorted:
        response = requests.get("http://ip-api.com/json/" + ip)#, verify=False)
        time.sleep(2) # 45 requests for 1 minutes
        data = response.json()

        # location = data["country"] + ", " + data["regionName"] + ", " + data["city"] #dans la cas où y pas de region ou city faire try 
        country = Tools.getIfInDict("country", data)
        region = Tools.getIfInDict("regionName", data)
        city = Tools.getIfInDict("city", data)
        if region != "" and country != "":
            region = ", " + region
        if city != "" and (country != "" or region != ""):
            city = ", " + city
        
        location = country + region + city
        owner = Tools.getIfInDict("org", data)

        for domain in domainsSorted[ip]:
            domain.setOwner(owner)
            domain.setLocation(location)
        

def findDomains(dns_str) -> list[Dns]:

    dns = Dns(dns_str)
    dns.findIpAddress()

    dd = Dnsdumpster()
    output_path = dd.dump(dns_str)
    dict_dump = Tools.xlsxToDict(output_path)
    os.remove(output_path)
    domains = initSubdomains(dict_dump)

    domains.append(dns)

    domainsSorted = sortDomainsByIp(domains)

    domainsSorted = getOwnerAndLocationByIp(domainsSorted)

    # for domain in domains:
    #     print(domain.toString())

    return domains

def scanServers(domains:list[Dns]):

    domainsSorted:dict[str, list[Dns]] = sortDomainsByIp(domains)
    
    for ip in domainsSorted:
        for i in range(len(domainsSorted[ip])):
            if i == 0 :
                domainsSorted[ip][i].findRecords()
                domainsSorted[ip][i].scan()
                domainsSorted[ip][i].findOS()
                domainsSorted[ip][i].findPorts()
                domainsSorted[ip][i].findCveForEachPorts()
            else:
                domainsSorted[ip][i].records = domainsSorted[ip][0].records
                domainsSorted[ip][i].os = domainsSorted[ip][0].os
                domainsSorted[ip][i].ports = domainsSorted[ip][0].ports
    return

def findEmails(dns_str) -> Email:
    
    outputPathFile = "./tmp/output.json"
    modules = modules_Spiderfoot.modules
    spiderfootPath = "./spiderfoot/sf.py"

    email = Email(outputPathFile)
    email.startSpiderFootScan(modules, dns_str, spiderfootPath)
    email.parseResponse()

    return email

def findCertificat(dns_str) -> Certificat:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dns_str, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dns_str) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert['issuer'])
                issued_on = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                expires_on = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

                # print("Émis par:", issuer['commonName'])
                # print("Valide du:", issued_on.strftime('%d-%m-%Y'))
                # print("Valide jusqu'au:", expires_on.strftime('%d-%m-%Y'))

                today = datetime.now()
                days_left = (expires_on - today).days

                return Certificat(issuer, issued_on, expires_on, days_left)

    except Exception as e:
        print(f"Erreur lors de la récupération du certificat pour {dns_str}: {e}")

    return

def clearDir(dirPath):
    if dirPath[-1] != "/":
        dirPath += "/"

    files = os.listdir(dirPath)

    for file in files:
        os.remove(dirPath+file)
    
    return

# def serialize(obj):
#     return obj.__dict__

def serialize_recursive(obj):
    if isinstance(obj, list):
        return [serialize_recursive(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return {key: serialize_recursive(value) if key != 'value' else serialize_recursive(getattr(obj, key)) for key, value in obj.__dict__.items()}
    elif isinstance(obj, dict):
        return {key: serialize_recursive(value) for key, value in obj.items()}
    else:
        return obj

def scan(dns_str):

    testingFront = True

    if testingFront:
        minSubdomainsNumber = 0
        maxSubomainsNumber = 50
        
        from random import randint, sample, choice
        from app.models.Port import Port
        from app.models.Service import Service
        from app.models.Cve import Cve
        import app.models.var as var

        nbDns = randint(minSubdomainsNumber, maxSubomainsNumber)
        domains = [Dns("test.com", choice(var.ip))]
        i = 0
        while i<nbDns:
            domains.append(Dns(choice(var.subdomains), choice(var.ip)))
            i+=1


        for domain in domains:

            ports = sample(var.ports, randint(0, len(var.ports)))

            for port in ports:
                
                cves = sample(var.cves, randint(0, len(var.cves)))

                service = Service({})
                service.name = choice(var.services)
                service.product = choice(var.products)
                service.version = choice(var.versions)
                service.cpe = choice(var.cpe)

                for cve_name in cves:
                    cve = Cve(cve_name, choice(var.descriptions), choice(var.cvsss))
                    service.cves.append(cve)
                
                
                p = Port({})
                p.service = service
                p.portNumber = port
                p.state = choice(var.states)

                domain.ports.append(p)

                


            domain.owner = var.owners[randint(0,len(var.owners)-1)]
            domain.location = var.locations[randint(0,len(var.locations)-1)]
            domain.os = var.os[randint(0,len(var.os)-1)]
            domain.records = var.records[randint(0,len(var.records)-1)]


        

        all_info = {"Domains": serialize_recursive(domains), "Email": Email("../tmp/").__dict__, "Certificat" : Certificat("Issuer", "10/03/2022", "29/04/2025", "368").__dict__}

        return all_info




    clearDir("../tmp/")
    domains = findDomains(dns_str) # doit retourner une list[Dns]
    scanServers(domains)

    all_info = {"Domains": domains, "Email": findEmails(dns_str), "Certificat" : findCertificat(dns_str)}

    return all_info

    # 

    # il faut donner un domaine
    # 
    # findDomains()
    # scanServer() on boucle
    # searchEmails() faut sortir email de dns
    # findCertificat() faut sortir certificat de dns aussi
    
    
    # print("end")