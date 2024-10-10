from app.models.Service import Service
import app.models.Tools as Tools

class Port:
    def __init__(self, all_info:dict):
        self.service = Service(all_info)
        self.portNumber:str = Tools.getIfInDict("port", all_info)
        self.state:str = Tools.getIfInDict("state", all_info)

    
    def findCves(self):
        self.service.findCves()
    

    def toString(self) -> str:
        string = "Port :" + self.portNumber + "\n"
        string += "State :" + self.state + "\n"
        string += self.service.toString()
        return string + "\n"