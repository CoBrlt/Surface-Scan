from flask import Flask

app = Flask(__name__)
app.secret_key = "(o_o)"

from app.Routes import *