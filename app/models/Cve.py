class Cve:
    def __init__(self, name:str, description:str, cvss:dict):
        self.name:str = name
        self.description:str = description
        self.cvss:dict = cvss


    def toString(self):
        return self.name+" "+self.description+" "+ str(self.cvss)  + "\n"