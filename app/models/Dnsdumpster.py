import requests
import re
import os
from bs4 import BeautifulSoup
class Dnsdumpster:
    def __init__(self):
        self.url = "https://dnsdumpster.com"
        self.headers = {
            "Referer":self.url
        }
        response = requests.get(self.url, headers=self.headers)#, verify=False)
        doc = BeautifulSoup(response.text.strip(), "html.parser")
        try:
			# locate the csrf token
            tag = doc.find("input", {"name":"csrfmiddlewaretoken"})
            self.csrftoken = tag['value']
			# to avoid a 403, the csrftoken cookie has to be set,
			# along with the referer.
            self.headers = {
                "Referer":self.url,
                "Cookie": "csrftoken="+self.csrftoken+";"
			}
        except:
            pass

    

    def dump(self, dns:str)->str:
        
        data = {"csrfmiddlewaretoken": self.csrftoken, "targetip": dns, "user":"free"} #charges utiles dans l'inspection réseaux
        response = requests.post("https://dnsdumpster.com", headers=self.headers, data=data)#, verify=False)

    
        soup = BeautifulSoup(response.content, "html.parser")
        path = soup.find("a", href=re.compile(r'^/static/xls/'))
        link = self.url + path.get("href")
        response = requests.get(link)#, verify=False)
        

        if response.status_code == 200:
            
            output_direction = "./tmp/"
            output_filename = "file.xlsx"
            os.makedirs(output_direction, exist_ok=True)

            output_path = output_direction + output_filename

            with open(output_path, "wb") as file:
                file.write(response.content)
            
            print("Dnsdumpster : Success")
            return output_path
        else:
            print("Dnsdumpster : Failed")
        
            return ""