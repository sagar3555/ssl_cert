import requests
import time
import datetime
from Send_Notifications import Get_Technical_Owner ,First_mail
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DBConnection_Sagar import Base,cert_data_sagar
import logging

logger_Insert_db_error = logging.getLogger('Certrenewal_Insert_db_error ')
Insert_db_error  = logging.FileHandler('E:\\4-FlaskForms\logs\Certrenewal_warnign_Insert_db_error.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
Insert_db_error.setFormatter(formatter)
logger_Insert_db_error.addHandler(Insert_db_error)
logger_Insert_db_error.setLevel(logging.WARNING)


logger_Insert_db = logging.getLogger('Certrenewal_Insert_db_info ')
Insert_db_info  = logging.FileHandler('E:\\4-FlaskForms\logs\Insert cert detail db.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
Insert_db_info.setFormatter(formatter)
logger_Insert_db.addHandler(Insert_db_info)
logger_Insert_db.setLevel(logging.INFO)








USERNAME = ""
PASSWORD = ""
formatDate = "%Y-%m-%d"
formatTime = "%H-%M-%S"
formatDateTime = "%b %d %H:%M:%S %Y %Z"
fmt   = "%Y-%m-%d %H:%M:%S"
prodServers = ['10.119.251.185','10.119.251.161','10.119.251.162',"10.119.251.166"]
ogranistation =""
city= "Stockholm"
state ="Stockholm"
country ="SE"
CN=""
SAN=""


engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def Insert_Into_Database (cert_name,common_name,organisation,ou,country,locality,email,state,technical_owner,expiration_date,renewal_status,serverip,partition):
    cert_data_obj= cert_data_sagar()
    cert_data_obj.cert_name=cert_name
    cert_data_obj.common_name=common_name
    cert_data_obj.orangnisation=organisation
    cert_data_obj.ou=ou
    cert_data_obj.country=country
    cert_data_obj.locality=locality
    cert_data_obj.email=email
    cert_data_obj.state=state
    cert_data_obj.technical_owner=technical_owner
    cert_data_obj.expiration_date=expiration_date
    cert_data_obj.renewal_status=renewal_status
    cert_data_obj.serverip=serverip
    cert_data_obj.partition=partition
    session.add(cert_data_obj)
    session.commit()



def getServerName(server):
    if server == "10.119.251.162":
        return "Internet/DMZ Production Load Balancer (seistolbp01)"
    elif server == "10.119.251.161":
        return "Internet/DMZ Verification Load Balancer (seistolbv01)"
    elif server == "10.119.251.185":
        return "Datacenter Production Load Balancer (sezstolbp01)"
    elif server == "10.119.251.166":
        return "Datacenter Test Load Balancer (sezstolbt02)"


def getCertInfo(server):
    req = requests.get("https://" + server + "/mgmt/tm/sys/file/ssl-cert?expandSubcollections=true",
                       auth=(USERNAME, PASSWORD), verify=False)
    res = req.json()
    return res['items']


def get_cert_parameters (json) :
    subjectraw =  json['subject']
    cert_name  =  json ['name']
    partition  = json['partition']
    attributes = subjectraw.split(",")
    #print(json)
    #print (attributes)
    subject = {}
    try  :
        for attr in attributes:
            #print(attr.split("=")[0] + " : " + attr.split("=")[1])
            subject[attr.split("=")[0]] = attr.split("=")[1]
    #check  keys in  the subject
        if 'O' not in subject:
            print("Missing O  key, setting O  to  ICA")
            subject['O']= "ICA AB"
        if 'OU' not in subject:
            print("Missing OU key ,setting OU  to  NETWORK  INFRA")
            subject['OU']= "NETWORK  INFRA"
        if 'CN' not in subject:
            print("Missing CN key  ,print invalid certificate")
        if 'L' not in subject:
            print("Missing L key ,setting L  to  Stockholm")
            subject['L'] = "Stockholm"
        if 'C' not in subject:
            print("Missing C key  ,setting C to  Sweden")
            subject['C']='SE'
        if 'emailAddress' not in  subject:
            print("Missing email key ,setting emailaddress to  cominfo@ica.se ")
            subject['emailAddress'] = 'cominfo@ica.se'
        if 'ST' not in subject:
            print("Missing ST key ,setting ST to  Stockholm ")
            subject['ST']='Stockholm'

    except :
        print(cert_name ," inside  exception" ,len(subject))
    return subject ,partition
def validate_certname():
    return False

def Cert_Info_To_DB():

    logger_Insert_db.info("Attempting to collect data from Load Balancers")

    for server in prodServers:
        print(server)
        logger_Insert_db.info("Connecting to load Balancer "+ server)
        items = getCertInfo(server)
        logger_Insert_db.info("Received  certificate data from " + server)
        for item in items:
            cert_name = item['name']
            if "CN=Issuing CA Device"in  item['issuer'] :
                temp  = datetime.datetime.strptime(item['expirationString'] , formatDateTime)
                certExpirationTime = datetime.datetime.strptime(str(temp.date()), formatDate)
                logger_Insert_db.info("Checking whether certificate expires witin 60 days :"+ cert_name)
                if (int((certExpirationTime.date() - datetime.datetime.date(datetime.datetime.now())).days)) > 450 and int(
                        (certExpirationTime.date() - datetime.datetime.date(datetime.datetime.now())).days) <= 800:
                    logger_Insert_db.info("Certificate expires with in 60 days " + cert_name)
                    logger_Insert_db.info("Collecting data for  " + cert_name)
                    subject,partition = get_cert_parameters(item)
                    technical_owner = Get_Technical_Owner(subject['OU'])
                    print(technical_owner,"technucal owner" ,cert_name)
                    if  cert_name=="testSndt.ica.ia-hc.net20180219.crt" :
                        try:
                            logger_Insert_db.info("Inserting collected  certificate details in Database : "+ cert_name +"  "+server)
                            Insert_Into_Database(cert_name,subject['CN'],subject['O'],subject['OU'],subject['C'],subject['L'],subject['emailAddress'],subject['ST'],technical_owner,certExpirationTime,
                                            "initial",server,partition)

                            logger_Insert_db.info("Insertion Sucessfully completed "+cert_name+"  "+server )
                            First_mail(cert_name,certExpirationTime.date(),technical_owner)
                        except Exception as e :
                            #print("Error While inserting data for certifcate "+ cert_name )

                            if "UNIQUE constraint failed:"  in str(e):
                                logger_Insert_db.info("Data for Vertificate already exists in database  " + cert_name + " : Primary Key Violation can be ignored"+"\n\n")
                            else  :
                                logger_Insert_db_error.error("Error While inserting data for certifcate "+ cert_name)
                                logger_Insert_db_error.error(e)
                else  :
                    logger_Insert_db.info("certificate not expiring in 60 days " + cert_name + "  " + server+"\n")
                    session.close()

def  get_database_data():
    session = DBSession()
    cert_d = session.query(cert_data_sagar).all()
    for cert in cert_d:
        if  cert.cert_name==  "testSndt.ica.ia-hc.net20180219.crt" :
            print(cert.common_name ,cert.country,cert.cert_name ," ",  cert.expiration_date ," ", cert.technical_owner ," ", cert.partition ,cert.verifier_email ,cert.dateTime1 ,cert.dateTime2   )
    session.close()
Cert_Info_To_DB()

get_database_data()

session.close()









