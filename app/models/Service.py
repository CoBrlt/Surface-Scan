import requests
import urllib3
import time
from app.models.Cve import Cve
import app.models.Tools as Tools

class Service:
    def __init__(self, all_info:dict):
        
        self.name:str = Tools.getIfInDict("name", all_info)
        self.product:str = Tools.getIfInDict("product", all_info)
        self.version:str = Tools.getIfInDict("version", all_info)
        self.cpe = self.editCpe(Tools.getIfInDict("cpe", all_info))
        self.cves:list[Cve] = []
        
        return
    
    def editCpe(self, cpe:str)->str:
        
        if self.name == "ssh" or self.product == "OpenSSH":
            v = self.version.split(" ")[0]
            cpe = "cpe:2.3:a:openbsd:openssh:"+v
        
        cpe = cpe.replace("cpe:/", "cpe:2.3:")


        if len(cpe.split(":")) < 6:
            cpe = ""
        

        return cpe
    
    def findCves(self):
        
        print("Getting CVE(s) for "+self.product+" ("+ self.cpe +")")

        if self.cpe ==  "":
            return ""
                
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="+ self.cpe +"&isVulnerable"
        #5 requests in 30 sec (soit une toutes les 6 secondes)
        time.sleep(7)
        #50 requests in 30 sec 

        response = requests.get(url)#, verify=False)
        
        if response.status_code != 200:
            return

        data = response.json()

        print("Number CVE : " + str(len(data["vulnerabilities"])))

        for vuln in data["vulnerabilities"]:
            name = vuln["cve"]["id"]
            for desc in vuln["cve"]["descriptions"]:
                if desc["lang"] == "en":
                    description = desc["value"]
                    break
            

            
            cvss = {'version': "", 'exploitabilityScore': "", 'impactScore': "",'baseScore': "", 'baseSeverity': ""}
            tab_cvss = []
            for metric in vuln["cve"]["metrics"]:
                cvss["version"] = vuln["cve"]["metrics"][metric][0]["cvssData"]["version"]
                cvss["exploitabilityScore"] = vuln["cve"]["metrics"][metric][0]["exploitabilityScore"]
                cvss["impactScore"] = vuln["cve"]["metrics"][metric][0]["impactScore"]
                cvss["baseScore"] = vuln["cve"]["metrics"][metric][0]["cvssData"]["baseScore"]
                
                if "baseSeverity" in vuln["cve"]["metrics"][metric][0] :
                    cvss["baseSeverity"] = vuln["cve"]["metrics"][metric][0]["baseSeverity"]
                elif "baseSeverity" in vuln["cve"]["metrics"][metric][0]["cvssData"]:
                    cvss["baseSeverity"] = vuln["cve"]["metrics"][metric][0]["cvssData"]["baseSeverity"]
                else:
                    cvss["baseSeverity"] = ""
                
                tab_cvss.append(cvss.copy())

            self.cves.append(Cve(name, description, tab_cvss))

        return
    
    def toString(self):
        string = ""

        string += "Name : " + self.name + "\n"
        string += "Product : " + self.product + "\n"
        string += "Version : " + self.version + "\n"
        string += "CPE : " + self.cpe + "\n"
        
        for cve in self.cves:
            string += cve.name + "\n"
        
        return string  + "\n"

