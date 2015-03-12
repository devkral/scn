
import hashlib
import logging
import os

from subprocess import Popen,PIPE
from OpenSSL import SSL,crypto

from scn_config import key_size


#not domain saved with cert but domain on server
def scn_verify_ncert(_domain,pub_cert,_certhash):
  temphash=hashlib.sha256(bytes(_domain,"utf8"))
  temphash.update(pub_cert)
  if temphash.hexdigest()==_certhash:
    return True
  else:
    return False
  
#not domain saved with cert but domain on server
def scn_gen_ncert(_domain,pub_cert):
  temphash=hashlib.sha256(bytes(_domain,"utf8"))
  temphash.update(pub_cert)
  return temphash.hexdigest() #str


def generate_certs(_path):
  genproc=None
  _passphrase=input("(optional) Enter passphrase for encrypting key:\n")
  if _passphrase=="":
    genproc=Popen(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:"+str(key_size), "-keyout",_path+".priv", "-out",_path+".pub"],stdin=PIPE,stdout=PIPE, stderr=PIPE,universal_newlines=True)
    _answer=genproc.communicate("IA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")
  else:
    genproc=Popen(["openssl", "req", "-x509", "-aes256", "-newkey", "rsa:"+str(key_size),"-keyout",_path+".priv", "-out",_path+".pub"], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    _answer=genproc.communicate(_passphrase.strip("\n")+"\n"+_passphrase.strip("\n")+"\nIA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")

  #logging.debug(_answer[0])
  if _answer[1]!="":
    logging.debug(_answer[1])

def check_certs(_path):
  if os.path.exists(_path+".priv")==False or os.path.exists(_path+".pub")==False:
    return False
  _key=None
  with open(_path+".priv", 'r') as readin:
    #def interact_wrap():
    #  return interact("Please enter passphrase")
    #,interact_wrap
    _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read())
  if _key is None:
    return False

  if os.path.exists(_path+".pub")==True:
    is_ok=False
    with open(_path+".pub", 'r') as readin:
      try:
        _c=SSL.Context(SSL.TLSv1_2_METHOD)
        #_c.use_privatekey(_key)
        _c.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,readin.read()))
        #_c.check_privatekey()
        is_ok=True
      except Exception as e:
        logging.error(e)
    if is_ok==True:
      return True
  return False
