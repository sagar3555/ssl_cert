import datetime
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DBConnection_Sagar import Base,cert_data_sagar
from OpenSSL import crypto, SSL
import subprocess
TYPE_RSA = crypto.TYPE_RSA
import requests,re,json
import logging

logger_certrenewal_process_error = logging.getLogger('Certrenewal_error ')
cert_renewal_error  = logging.FileHandler('E:\\4-FlaskForms\logs\Certrenewal_error.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
cert_renewal_error.setFormatter(formatter)
logger_certrenewal_process_error.addHandler(cert_renewal_error)
logger_certrenewal_process_error.setLevel(logging.WARNING)



logger_certrenewal_process_info = logging.getLogger('Certrenewal_process_info ')
certrenewal_process_info  = logging.FileHandler('E:\\4-FlaskForms\logs\Certrenewal_process_info.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
certrenewal_process_info.setFormatter(formatter)
logger_certrenewal_process_info.addHandler(certrenewal_process_info)
logger_certrenewal_process_info.setLevel(logging.INFO)










engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

#logger = logging.getLogger('Renew_cert')
#log_handler = logging.Formatter('renew_cert_log.log')
#log_handler.setFormatter(log_handler)
#logger.addHandler(log_handler)
#logger.setLevel(logging.INFO)

username=""
password=""

hostname  = "10.119.251.185"
server  = hostname







def getFileName(certname):
    filename =""
    name= certname.split('.')[0]

    filename =re.sub('\d','',str(os.path.splitext(certname)[0]))+re.sub("-","",str(datetime.datetime.now().date()))
    return filename

def  Check_Key_File (certname) :
    logger_certrenewal_process_info.info("inside method : Check_Key_File(" + certname + ")")
    logger_certrenewal_process_info.info("checking for key file for certificate" + certname + ")")
    certname = ''.join([i for i in certname if not i.isdigit()])
    key_and_csr_dir = r'E:\4-FlaskForms\key and csr'

    key_flag = True
    for name in os.listdir(key_and_csr_dir):
        print(name )
        if certname in name and  name.endswith(".key"):

            key_flag = False
            logger_certrenewal_process_info.info("key file found for "+ certname + ")")


    return key_flag





#Check_Key_File("abc")

def  Check_CSR_File (certname) :
    logger_certrenewal_process_info.info("inside method : Check_CSR_File(" + certname + ")")
    certname = ''.join([i for i in certname if not i.isdigit()])
    key_and_csr_dir = r'E:\4-FlaskForms\key and csr'

    csr_flag = True
    for name in os.listdir(key_and_csr_dir):
        if certname in name and name.endswith(".csr"):
            logger_certrenewal_process_info.info("csr file found for certificate :" + certname + ")")
            csr_flag = False

    return csr_flag


def Generate_Key_File(type, bits ,certname):
    logger_certrenewal_process_info.info("inside  method : Generate_Key_File(TYPE_RSA, 2048," + certname + ")")
    try :
        logger_certrenewal_process_info.info("calling method : Check_Key_File(" + certname + ")")
        if Check_Key_File(certname) :
            logger_certrenewal_process_info.info("key file does not found for " + certname + ")")
            logger_certrenewal_process_info.info("generating key file  for " + certname + ")")

            temp = str(datetime.datetime.now().date()).replace("-","")
            certname = ''.join([i for i in certname if not i.isdigit()])
            certname = certname.replace(".crt", "")
            path  = os.path.join( "E:\\","4-FlaskForms","key and csr")
            keyfile = path+r'\"'+certname+temp+".key"
            keyfile=keyfile.replace('"',"")
            key = crypto.PKey()
            key.generate_key(type, bits)
            f = open(keyfile, "wb")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            f.close()
            logger_certrenewal_process_info.info("key file generated  for " + certname + ")")
            print ("key generated")
            return key
    except Exception as e  :
        pass
    finally :
        pass


#Generate_Key_File(TYPE_RSA,2048,"ver.se.ica.se_cert_20160427")


def Generate_CSR_File (certname) :
    logger_certrenewal_process_info.info("Inside  method : Generate_CSR_File(" + certname + ")")
    logger_certrenewal_process_info.info("calling method : Generate_Key_File(TYPE_RSA, 2048," + certname + ")")
    key = Generate_Key_File(TYPE_RSA, 2048, certname)
    logger_certrenewal_process_info.info("calling method : Check_CSR_File(" + certname + ")")
    if Check_CSR_File(certname) :
        logger_certrenewal_process_info.info("csr file does not found for " + certname + ")")
        logger_certrenewal_process_info.info("generating csr file  for " + certname + ")")
        logger_certrenewal_process_info.info("connecting to database")

        engine = create_engine(r'sqlite:///E:\Scripts\Project_Cert\certdetail_sagar.db')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        cert_d = session.query(cert_data_sagar).all()
        for cert in cert_d:
            if cert.cert_name == certname :
                logger_certrenewal_process_info.info("collecting data for csr generation :"+certname)

                req = crypto.X509Req()
                ss = []
                ss.append("DNS:%s" % cert.common_name)
                ss.append("DNS:%s" % cert.common_name.split('.')[0])
                print(ss)
                req.get_subject().CN = cert.common_name
                req.get_subject().countryName = cert.country
                req.get_subject().stateOrProvinceName = cert.state
                req.get_subject().localityName =cert.locality
                req.get_subject().organizationName = cert.orangnisation
                req.get_subject().organizationalUnitName = cert.ou
                req.get_subject().emailAddress = cert.email
                req.add_extensions([crypto.X509Extension(b"subjectAltName", False, ",".join(ss).encode())])
                req.set_pubkey(key)
                req.sign(key, "sha256")

                temp = str(datetime.datetime.now().date()).replace("-", "")
                certname = ''.join([i for i in certname if not i.isdigit()])
                path = os.path.join("E:\\", "4-FlaskForms", "key and csr")
                certname = certname.replace(".crt","")
                csrfile = path + r'\"' + certname + temp + ".csr"
                csrfile = csrfile.replace('"', "")
                f = open(csrfile, "wb")
                f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
                f.close()
                session.close()
                logger_certrenewal_process_info.info("csr file generated for " + certname + ")")
                print ("csr generated")
                return certname + temp + ".csr"


def startupload(keyname,newcertname,oldcertname):
    logger_certrenewal_process_info.info("inside method startupload(" + keyname + "," + newcertname + "," + oldcertname + ")")
    logger_certrenewal_process_info.info("Building the Auth object for uploading certificate ")
    # Build the auth object for uploading the cert/key
    b_url_base = 'https://%s/mgmt/tm' %hostname
    b = requests.session()
    b.auth = (username, password)
    b.verify = False
    b.headers.update({'Content-Type':'application/json'})
    filepath=list()
    filepath.append(newcertname)
    filepath.append(keyname)
    logger_certrenewal_process_info.info("upload the key/cert files to BIG-IP. Default location is /var/config/rest/downloads/")
    #upload the key/cert files to BIG-IP. Default location is /var/config/rest/downloads/
    _upload(hostname, (username, password), filepath[0])
    _upload(hostname, (username, password), filepath[1])
    logger_certrenewal_process_info.info("uploading the key/cert files to BIG-IP. Default location is sucessful")
    # Map the key/cert files to a BIG-IP cert file object for use in ssl profiles
    logger_certrenewal_process_info.info("Maping the key/cert files to a BIG-IP cert file object for use in ssl profiles")
    #logger_certrenewal_process_info.info("calling method :create_cert_obj("+b+","+b_url_base+","+filepath)
    certname, keyname = create_cert_obj(b, b_url_base, filepath)
    logger_certrenewal_process_info.info("Maping Cert/key to File Object sucessful")
    print(str(certname),str(keyname))
    # Use the new cert file object to create an ssl profile
    logger_certrenewal_process_info.info("Using the new cert file object to create an ssl profile")
   #logger_certrenewal_process_info.info("calling method :create_ssl_profile("+b+","+b_url_base+","+certname+","+keyname+","+oldcertname+")")
    create_ssl_profile(b, b_url_base, certname, keyname ,oldcertname)

def getSslProfileData(server):
    req = requests.get("https://" + server + "/mgmt/tm/ltm/profile/client-ssl?expandSubcollections=true",
                       auth=(username, password), verify=False)
    result = req.json()
    return result['items']

def getSslProfileName(certname):
    ssl_profile_data = getSslProfileData(hostname)
    ssl_profile_name=""
    for data in ssl_profile_data:
        if re.search(certname,data['cert']):
            ssl_profile_name=data['name']
    return ssl_profile_name




def _upload(host, creds, fp):

    chunk_size = 512 * 1024
    headers = {
        'Content-Type': 'application/octet-stream'
    }
    fileobj = open(fp, 'rb')
    filename = os.path.basename(fp)
    uri = 'https://%s/mgmt/shared/file-transfer/uploads/%s' % (host, filename)

    requests.packages.urllib3.disable_warnings()
    size = os.path.getsize(fp)

    start = 0

    while True:
        file_slice = fileobj.read(chunk_size)
        if not file_slice:
            break

        current_bytes = len(file_slice)
        if current_bytes < chunk_size:
            end = size
        else:
            end = start + current_bytes

        content_range = "%s-%s/%s" % (start, end - 1, size)
        headers['Content-Range'] = content_range
        requests.post(uri,
                      auth=creds,
                      data=file_slice,
                      headers=headers,
                      verify=False)

        start += current_bytes

def create_cert_obj(bigip, b_url, files):
    #logger_certrenewal_process_info.info("inside  method :create_cert_obj(" + bigip + "," + b_url + "," + files+")")

    f1 = os.path.basename(files[0])
    f2 = os.path.basename(files[1])
    if f1.endswith('.crt'):
        certfilename = f1
        keyfilename = f2
    else:
        keyfilename = f1
        certfilename = f2

    certname = str(os.path.splitext(f1)[0])

    payload = {}
    payload['command'] = 'install'
    payload['name'] = certname

    # Map Cert to File Object
    logger_certrenewal_process_info.info("Maping Cert to File Object")
    payload['from-local-file'] = '/var/config/rest/downloads/%s' % certfilename
    bigip.post('%s/sys/crypto/cert' % b_url, json.dumps(payload))

    # Map Key to File Object
    logger_certrenewal_process_info.info("Maping key to File Object")
    payload['from-local-file'] = '/var/config/rest/downloads/%s' % keyfilename
    bigip.post('%s/sys/crypto/key' % b_url, json.dumps(payload))

    return certfilename, keyfilename

def create_ssl_profile(bigip,server, certname, keyname ,oldcertname):
    #logger_certrenewal_process_info.info(
        #"calling method :create_ssl_profile(" + bigip + "," + server + "," + certname + "," + keyname + "," + oldcertname + ")")

    payload = {}
    #payload['name'] = certname.split('.')[0]+"_clientssl"
    #profilename=certname.split('.')[0]+"_clientssl"
    payload['cert'] = certname
    payload['key'] = keyname
    parition = "DC_TEST"
    profilename = getSslProfileName(oldcertname)
    #bigip.post('%s/ltm/profile/client-ssl' % b_url, json.dumps(payload))
    if profilename:
        r= bigip.patch('https://10.119.251.185/mgmt/tm/ltm/profile/client-ssl/'+'~'+parition+'~'+profilename,json.dumps(payload))
        #logger.info("Certificate Successfully Renewed")
    else:
        print("Unable to  profile name")
        #logger.error("Unable to  get profile  name for " + oldcertname)
    print(r.text)



def Generate_certificate (certname) :
     logger_certrenewal_process_info.info("Inside method : Generate_certificate ")
     logger_certrenewal_process_info.info("calling method : Generate_CSR_File("+certname+")")
     csrfile = Generate_CSR_File(certname)
     print (csrfile)
     logger_certrenewal_process_info.info("Generating certificate :" + certname + ")")
     powerShellPath = r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe'
     powershellfile = r'E:\4-FlaskForms\CA_Admins.ps1'
    # # subprocess.Popen("powershell.exe "+'CA_Admins.ps1')
     p = subprocess.Popen([powerShellPath, '-ExecutionPolicy', 'Unrestricted', powershellfile, "-CSRName " + csrfile]
                          , stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     output, error = p.communicate()
     print((str(output)).encode('utf-8'), " ", (str(error)).encode('utf-8'))
     rc = p.returncode
     print (rc)

     if rc==0:
        logger_certrenewal_process_info.info("searching key for certificate : " + certname + ")")
        key_and_csr_dir = r'E:\4-FlaskForms\key and csr'
        keyname= getFileName(certname)+".key"
        newcertname = getFileName(certname)+".crt"

        key_path = os.path.join("E:\\", "4-FlaskForms", "key and csr", keyname)
        logger_certrenewal_process_info.info("key file path for :" + certname +"-"+ key_path)

        logger_certrenewal_process_info.info("searching crt for certificate : " + certname + ")")
        cert_dir = r"E:\4-FlaskForms\Certificate"

        cert_path = os.path.join("E:\\", "4-FlaskForms", "Certificate", newcertname)
        logger_certrenewal_process_info.info("crt file path for :" + certname + "-" + cert_path)

        print(key_path)
        print(cert_path)
        logger_certrenewal_process_info.info("starting upload of certificate: "+ newcertname)
        logger_certrenewal_process_info.info("calling method startupload(" +key_path+","+cert_path+","+certname+")")
        startupload(key_path,cert_path,certname)
        print("Operation succesfull")
     else:
        print("Error in geneating certificate")






logger_certrenewal_process_info.info("Establishing coonection with Database" )
cert_d = session.query(cert_data_sagar).all()
logger_certrenewal_process_info.info("Connection established with Database" )
for cert in cert_d:

    try :
        logger_certrenewal_process_info.info("checking whether certificate can be renewed :" + cert.cert_name  )
        if  cert.dateTime1 < datetime.datetime.now() <cert.dateTime2 :
            logger_certrenewal_process_info,info("starting renewal of certificate :"+cert.cert_name )
            Generate_certificate(cert.cert_name)





            print ("True")
        else :
            logger_certrenewal_process_info.info("Certificate can not be renewed :" + cert.cert_name)

    except Exception as e :
        if  "unorderable types: NoneType() < datetime.datetime()" in str(e) :
            logger_certrenewal_process_info.info("Certificate can not be renewed now")
        else  :
            logger_certrenewal_process_error.error(cert.cert_name+" :" +"\n"  + str(e))
            print (e)

#Generate_certificate("testSndt.ica.ia-hc.net20180219.crt")
