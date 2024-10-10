import os
import subprocess
import json
import re

class Email:
    def __init__(self, outputPathFile:str):
        self.outputPathFile = outputPathFile
        self.emails:list[str] = []
    
    def startSpiderFootScan(self, modules:list[str], dns:str, spiderfootPath:str):

        str_modules = ""
        for module in modules:
            str_modules += module + ","
        str_modules = str_modules[:-1]
        
        command = "python " + spiderfootPath + " -s " + dns + " -o json -m " + str_modules + " > " + self.outputPathFile
        
        subprocess.run(command, shell=True)
        print("finish finish")

    
    def parseResponse(self):
        
        try:
            fichier = open(self.outputPathFile, "r")
            json_data = fichier.read()
            print(json_data)
        except FileNotFoundError:
            print(f"Le fichier '{self.outputPathFile}' n'existe pas.")
        except Exception as e:
            print(f"Une erreur s'est produite : {e}")

        if json_data == None:
            return
        
        pattern = r'\[.*\]'
        match = re.search(pattern, json_data)
        if match:
            json_data = "[" + json_data[:match.start()] + "]"
        
        data = json.loads(json_data)


        for info in data:
            if info["type"] == "Email Address":
                self.emails.append(info["data"])

        os.remove(self.outputPathFile)

        return