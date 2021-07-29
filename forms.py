import subprocess
import re
import datetime
import sys
from pypyodbc import connect

from flask import Flask, render_template, flash, request ,session ,redirect ,url_for,g
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DBConnection_Sagar import Base,cert_data_sagar
from sqlalchemy import update










 #r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db'

# App config.
def Validate_Date (date1 , date2) :
    try  :
        print("inside verify date time 1")
        fmt = "%Y-%m-%d %H:%M"

        temp1  = date1.replace("T" , " ")
        temp1 = datetime.datetime.strptime(temp1, fmt)

        temp2 = date2.replace("T"," ")
        temp2 = datetime.datetime.strptime(temp2,fmt)

        current_date_time  = datetime.datetime.now()

        #print ((temp1-current_date_time).total_seconds(),"1")
        #print ((temp2-temp1).total_seconds(),"2")

        if  (temp1-current_date_time).total_seconds() > 50 and (temp2-temp1).total_seconds() > 7200  :
             print ("inside verify date time 2")
             return True
        else  :
            return False
    except Exception  as e   :
        print (e)
        return False

def Validate_Verifier_email_id (email) :

    try  :
        print ("inside validate verifier  email addr ")
        fh = open("hello.ps1", "w+")
        fh.write("import-module activedirectory \n")
        fh.write("Get-ADUser -Filter {mail -eq "+"'"+email+"'"+"}")
        fh.close()
        ch = subprocess.Popen([r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe', r"E:\4-FlaskForms\hello.ps1"], shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ch.communicate()
        print(stdout.decode(), len(stdout.decode()),stderr.decode(),"hi")
        if len(stdout.decode()) > 0 :
            return True
        else :
            return False
    except Exception as e   :
        print (e)
        return False



def Validate_name (cert_name) :
    try :
        engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()

        cert_d = session.query(cert_data_sagar).all()
        Flag = False
        for cert in cert_d:
            if  cert.cert_name == cert_name :
                Flag = True
                break
        if Flag  ==  True :
            session.close()
            return True

        elif Flag  == False :
            session.close()
            return False
    except Exception as e  :
        session.close()
        print (e)
        return False



def Update_Details_sql_db (cert_name , dateandtime1 , dateandtime2 , email) :
    try :
        fmt = "%Y-%m-%d %H:%M:%S"

        temp1 = dateandtime1.replace("T", " ")+ ":00"
        temp1 = datetime.datetime.strptime(temp1, fmt)

        temp2 = dateandtime2.replace("T", " ")+":00"
        temp2 = datetime.datetime.strptime(temp2, fmt)
        engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()

        cert_d = session.query(cert_data_sagar).all()
        for cert in cert_d:
            if  cert.cert_name == cert_name :
                cert.verifier_email = email
                session.commit()
                cert.dateTime1 = temp1
                session.commit()
                cert.dateTime2 = temp2
                session.commit()
                cert.renewal_status = "details received for renewal"
                session.commit()
                session.close()
        print  ("updation completed ")






        #connection = connect('Driver={SQL Server};''Server=SEZVM2037T\GREJT;''Database=SqlAutomation;''port=1449;')
        #cursor = connection.cursor()
        #cursor.execute('UPDATE Certificates_To_Be_Renewed SET Renewal_Date1 ='+"'"+temp1+"'"+',Renewal_Date2 ='+"'"+temp2+"'"+',Verifier_Email='+"'"+email+"'"+',Details_Received ='+"'Y'"+' WHERE Certificate_Name ='+"'"+cert_name+"'")
        #connection.commit()
        #connection.close()
    except Exception as e  :
        session.close()
        print (e)
        print ("Error occured")



DEBUG = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
 
class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    password = TextField('Password:', validators=[validators.required(), validators.Length(min=3, max=35)])
    date  = TextField('dateandtime:' ,validators=[validators.required(), validators.Length(min=3, max=35)])

class LoginForm(Form):
    login_id = TextField('Name:', validators=[validators.required()])
    password = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])

class certdataForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    F5_IP_Address = TextField('F5_IP_Address', validators=[validators.required()])
    Partition = TextField('Partition', validators=[validators.required()])
    OU =  TextField('OU', validators=[validators.required()])
    orangnisation = TextField('orangnisation', validators=[validators.required()])
    country= TextField('country', validators=[validators.required()])
    state = TextField('state', validators=[validators.required()])
    Locality =  TextField('Locality', validators=[validators.required()])
    Technical_Owner =  TextField('Technical Owner', validators=[validators.required()])
    Expiry_Date = TextField('Expiry Date ', validators=[validators.required()])
    Status =  TextField('Status', validators=[validators.required()])
    Datetime1 = TextField('Datetime1', validators=[validators.required()])
    Datetime2 = TextField('Datetime2', validators=[validators.required()])
    






@app.route("/login",methods=['GET', 'POST'])
def login() :
    form = LoginForm(request.form)
    if request.method == 'POST':
        session.pop('user',None)

        loginid = request.form['login_id']
        password = request.form['password']
        #print(loginid , password)

        fh = open("VerifyCredentials.ps1", "w+")
        fh.write("function Test-ADCredential {\n \
                [CmdletBinding()]\n \
                 Param\n \
                (\n \
                    [string]$UserName,\n\
                    [string]$Password \n\
                )\n\
                if (!($UserName) -or !($Password)) {\n\
                Write-Warning 'Test-ADCredential: Please specify both user name and password'\n\
                } else {\n\
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement\n\
                $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')\n\
                $DS.ValidateCredentials($UserName, $Password)\n\
                }\n\
                } \n ")
        fh.write("Test-ADCredential -username "+ loginid +"  -password "+ password)
        fh.close()

        powerShellPath = r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe'
        powershellfile = r'E:\4-FlaskForms\VerifyCredentials.ps1'
        # # subprocess.Popen("powershell.exe "+'CA_Admins.ps1')
        p = subprocess.Popen([powerShellPath, '-ExecutionPolicy', 'Unrestricted', powershellfile, "Test-ADCredential -username "+ loginid +" "+" -Password "+" "+ password], shell = True ,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        temp1= stdout.decode()

        fh = open("verifynetwokuser.ps1", "w+")
        fh.write("import-module activedirectory \n Get-ADPrincipalGroupMembership "+"'"+loginid+"'"+" | select name")
        fh.close()

        ch = subprocess.Popen([r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe','-ExecutionPolicy', 'Unrestricted', r"E:\4-FlaskForms\verifynetwokuser.ps1"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ch.communicate()
        temp2 = stdout.decode()
        network_user = False
        if "Network-Tech" in temp2 :
            network_user = True

        print(network_user)

        if "True" in temp1 and network_user :
            session['user'] = loginid
            #print("credentila verified")
            return redirect(url_for("Admin_login"))

        elif "True" in temp1 :
            session['user'] = loginid
            return redirect(url_for("Normal_User_login"))

        else :
            render_template("login.html", form=form)

    return render_template("login.html", form=form)

@app.route("/adminlogin",methods=['GET', 'POST'])
def Admin_login() :
    if  g.user :
        return render_template("adminloginpage.html")
    else  :
        return redirect(url_for("login"))

@app.route("/userlogin",methods=['GET', 'POST'])
def Normal_User_login() :
        if g.user:
            return render_template("normaluserlogin.html")
        else:
            return redirect(url_for("login"))


@app.before_request
def before_request() :
    g.user = None
    if 'user' in session :
        g.user  = session['user']





@app.route("/renewalform", methods=['GET', 'POST'])
def hello1():
    if g.user :
        form = ReusableForm(request.form)
        print (form.errors)
        if request.method == 'POST':
            name=request.form['name']
            dateandtime1=request.form['dateandtime1']
            email=request.form['email']
            dateandtime2 = request.form['dateandtime2']
            print (name, " ", email, " ", dateandtime1 ,dateandtime2)

            #print (Validate_Verifier_email_id(email))
            #print (Validate_Date(dateandtime1 , dateandtime2))
            print (Validate_name(name))
            if form.validate :
                if Validate_name(name)==True and Validate_Date(dateandtime1,dateandtime2) and Validate_Verifier_email_id(email) :
                    try :
                        Update_Details_sql_db(name,dateandtime1,dateandtime2,email)
                    except :
                        flash ("Error  occured")

                    flash('Thanks for submitting details for certificate : ' + name)
                else:
                    error_string = "Error : "
                    if Validate_name(name) == False  or Validate_name(name)==None:
                        error_string+="please check the certificate name , "
                    if Validate_Date(dateandtime1,dateandtime2) == False :
                        error_string+= "please check the submitted date and time for renewal it should be according to mentioned guidelines ,"
                    if Validate_Verifier_email_id(email) == False :
                        error_string+= "Please check provided email address ."

                    flash(error_string)

        return render_template("hello2.html", form=form)
    return redirect(url_for("login"))




@app.route("/logout",methods=['GET', 'POST'])
def logout() :
    session.pop('user' ,None)
    return "You Have been logged out"

@app.route("/certdata1", methods=['GET', 'POST'])
def Certdata():
    if g.user :
        fh = open("verifynetwokuser.ps1", "w+")
        fh.write(
            "import-module activedirectory \n Get-ADPrincipalGroupMembership " + "'" + g.user + "'" + " | select name")
        fh.close()

        ch = subprocess.Popen(
            [r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe', '-ExecutionPolicy', 'Unrestricted',
             r"E:\4-FlaskForms\verifynetwokuser.ps1"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ch.communicate()
        temp2 = stdout.decode()
        network_user = False
        if "Network-Tech" in temp2:
            network_user = True

        print(network_user)

        if  network_user:




            html_string = "<html><body><head>\
               <title>Certificate Renewal Data</title>\
               <link rel='stylesheet' media='screen' href ='static/bootstrap.min.css'>\
               <link rel='stylesheet' href='static/bootstrap-theme.min.css'> \
               </head>\
            <div class="+"'"+"container"+"'"+">\
            <div style="+"'"+"float: left;"+"'"+"><a href="+"'"+"https://10.107.198.101/adminlogin"+"'"+">Click Here To Go Back</a></div> \
            <div style ="+"'"+"float: right;"+"'"+"> <a href="+"'"+"https://10.107.198.101/logout"+"'"+"> Click Here To Logout </a> </div> </div> \
            <table class="+"table"+">\
              <thead>\
              <tr> \
                <th>Certificate Name</th> <th>F5 IP Address</th> <th>Partition</th><th>OU</th><th>Locality</th>\
                <th>Technical Owner</th>\
                <th>Expiry Date</th>\
                <th>Status</th>\
                 <th>Datetime1</th><th>Datetime2</th> \
              </tr>\
            </thead>"
            engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
            Base.metadata.bind = engine
            DBSession = sessionmaker(bind=engine)
            session = DBSession()
            cert_d = session.query(cert_data_sagar).all()

            for cert in cert_d :
                table_rw_class = ''
                if cert.renewal_status.lower()=="initial" or cert.renewal_status.lower() =="intial" :
                    table_rw_class = "info"
                elif cert.renewal_status.lower() == "second notification sent" :
                    table_rw_class = "warning"
                elif cert.renewal_status.lower() == "final notification sent" :
                    table_rw_class = "danger"
                temp = "<tr class ="+table_rw_class+" ><td>" + str(cert.common_name) + "</td>" +"<td >" +str(cert.serverip)+"</td>"+"<td >" +str(cert.partition)+"</td>"+"<td >" +str(cert.ou)+"</td>"+"<td >" +str(cert.locality)+"</td>"+"<td >" +str(cert.technical_owner)+"</td>" + "<td>" + str(cert.expiration_date)[:11] + "</td>" +"<td>"+str(cert.renewal_status) + "</td>" +"<td>"+ str(cert.dateTime1) + "</td>"+"<td>"+ str(cert.dateTime2) + "</td></tr>\n"
                html_string += temp

            html_string+="</body></html>"
            session.close()
            fh = open("E:\\4-FlaskForms\\templates\certdata.html", "w+")
            fh.write(html_string)
            fh.close()
            return render_template("certdata.html")
        else:
            return redirect(url_for("Access_Denied"))
    else  :
        return  redirect(url_for("login"))

@app.route("/accessdenied", methods=['GET', 'POST'])
def Access_Denied():
    return render_template("accessdenied.html")

@app.route("/" ,methods=['GET', 'POST'])
def Index():
    return redirect(url_for("login"))

@app.route("/certdata" ,methods=['GET', 'POST'])
def Certdata1():

    if g.user :
        fh = open("verifynetwokuser.ps1", "w+")
        fh.write(
            "import-module activedirectory \n Get-ADPrincipalGroupMembership " + "'" + g.user + "'" + " | select name")
        fh.close()

        ch = subprocess.Popen(
            [r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe', '-ExecutionPolicy', 'Unrestricted',
             r"E:\4-FlaskForms\verifynetwokuser.ps1"], shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ch.communicate()
        temp2 = stdout.decode()
        network_user = False
        if "Network-Tech" in temp2:
            network_user = True

        print(network_user)

        if  network_user:

            form = certdataForm(request.form)
            if request.method == 'POST':
                name = request.form['name']
                ou = request.form['OU']
                orangnisation = request.form['orangnisation']
                country = request.form['country']
                state = request.form['state']
                locality = request.form['Locality']
                technical_owner = request.form['Technical Owner']

                print(name,ou,orangnisation ,country , state ,locality ,technical_owner)
                engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
                Base.metadata.bind = engine
                DBSession = sessionmaker(bind=engine)
                session = DBSession()
                cert_d = session.query(cert_data_sagar).all()
                for cert in cert_d:
                    if  cert.common_name == name :
                        cert.ou = ou
                        cert.orangnisation = orangnisation
                        cert.country = country
                        cert.state = state
                        cert.locality = locality
                        cert.technical_owner = technical_owner
                        session.commit()
                session.close()

            html_string = '<html>\
            <body>\
            <head>\
            <link rel="stylesheet" media="screen" href ="static/bootstrap.min.css">\
            <link rel="stylesheet" href="static/bootstrap-theme.min.css">\
            <style>\
            input[type="text"] { font-size: 9px; }\
            </style>\
            </head> \
            <table class="table table-condensed"> \
            <th>\
            <tr>\
            <td> <input style="border:none;background:none;resize:horizontal;" type="text" class="form-control" id="name" name="name" value="Cert Name" readonly ></td> \
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="F5_IP_Address" name="F5_IP_Address" value="F5 IP Address" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Partition" name="Partition" value="Partition" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="OU" name="OU" value="OU" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="orangnisation" name="orangnisation" value="orangnisation" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="country" name="country" value="country" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="state" name="state" value="state" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Locality" name="Locality" value="Locality" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none"  type="text" class="form-control" id="Technical Owner" name="Technical Owner" value="Technical Owner"></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Expiry Date" name="Expiry Date" value="Expiry Date" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Status" name="Status" value="Status" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Datetime1" name="Datetime1" value="Datetime1" readonly  ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Datetime2" name="Datetime2" value="Datetime2" readonly ></td>\
            <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="save" name="save" value="Save" ></td> </tr></th>'

            engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
            Base.metadata.bind = engine
            DBSession = sessionmaker(bind=engine)
            session = DBSession()
            cert_d = session.query(cert_data_sagar).all()
            for cert in cert_d:

                table_rw_class = 'info'
                if cert.renewal_status.lower() == "initial" or cert.renewal_status.lower() == "intial":
                    table_rw_class = "info"
                elif cert.renewal_status.lower() == "second notification sent":
                    table_rw_class = "warning"
                elif cert.renewal_status.lower() == "final notification sent":
                    table_rw_class = "danger"
                temp  =  '<tr class ='+table_rw_class+'> \
                    <form method="Post" action="" >\
                    <div class="form-group">\
                    <td> <input style="border:none" type="text" class="form-control" id="name" name="name" value='+'"'+cert.common_name+'"'+'readonly ></td> \
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="F5_IP_Address" name="F5_IP_Address" value='+'"'+cert.serverip+'"'+' readonly ></td>\
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="Partition" name="Partition" value='+'"'+cert.partition+'"'+' readonly  ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="OU" name="OU" value='+'"'+cert.ou+'"'+' ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="orangnisation" name="orangnisation" value=' + '"' + cert.orangnisation + '"' + ' ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="country" name="country" value=' + '"' + cert.country + '"' + ' ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="state" name="state" value=' + '"' + cert.state + '"' + ' ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none" type="text" class="form-control" id="Locality" name="Locality" value=' + '"' + cert.locality + '"' + '  ></td>\
                    <td> <input style="border:none;resize:horizontal;background:none"  type="text" class="form-control" id="Technical Owner" name="Technical Owner" value=' + '"' + cert.technical_owner + '"' + ' ></td>\
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="Expiry Date" name="Expiry Date" value=' + '"' + str(cert.expiration_date)[:11]+ '"' + ' readonly ></td>\
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="Status" name="Status" value=' + '"' + str(cert.renewal_status)+ '"' + ' readonly ></td>\
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="Datetime1" name="Datetime1" value=' + '"' + str(cert.dateTime1)+ '"' + ' readonly ></td>\
                    <td> <input style="border:none;resize:horizontal" type="text" class="form-control" id="Datetime2" name="Datetime2" value=' + '"' + str(cert.dateTime2)+ '"' + ' readonly ></td>\
                    <td> <button type="submit" onClick="confSubmit(this.form)" class="btn btn-success">Submit</button></td>\
                    </div>\
                    </form>\
                    </tr>'
                html_string+=temp
                session.close()


            html_string+="</table><Body></html>"
            return html_string
        else:
            return redirect(url_for("Access_Denied"))
    else:
        return redirect(url_for("login"))




if __name__ == "__main__":
    app.run( host = "10.107.198.101", port=443,threaded = True,ssl_context='adhoc')
