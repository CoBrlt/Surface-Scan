import re
from flask import redirect, request, render_template, session
from app.App import app
from app.models.Scanner import scan

@app.route('/', methods = ['POST'])
def input_post():

    data = request.form

    session["DNSInput"] = data.get("DNSInput")

    #faire une petite regex ici
    
    return redirect("/scanning")



@app.route('/', methods = ['GET'])
def input_get():

    return render_template("form/form.html")




@app.route('/scanning')
def scanning():
    dnsName = session.get("DNSInput")
    all_info = scan(dnsName) #  ça lance un scan complet complet
    session["all_info"] = all_info
    print(all_info)

       


    return all_info

@app.route('/dashboard')
def dashborad():
    print("a")