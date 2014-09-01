#! /usr/bin/env python3

#LICENSE: my code: bsd 3-clauses, openssl: bsd 4-clausea


import socket
import struct
import re
import sys
import pprint
import traceback
import os
import os.path
import hashlib
from subprocess import Popen,PIPE

from OpenSSL import SSL,crypto




#import Enum from enum

from scn_config import debug_mode, show_error_mode, buffersize, max_cert_size, max_cmd_size, min_name_length, max_name_length,max_message_length, max_user_services, max_service_nodes, secret_size, key_size,protcount_max,hash_hex_size

# from scn_config import scn_client_port

sepm="\x1D" #seperate messages (consist of commands)
sepc="\x1E" #seperate commands
sepu="\x1F" #seperate units (part of command, convention)
  


def check_hash(_hashstr):
  if len(_hashstr)==64 and all(c in "0123456789abcdef" for c in _hashstr):
    return True
  return False
#check if invalid non blob (e.g. name, command)
_check_invalid_chars=re.compile("[\$\0'\"\n\r\b\u001a\u007F\u001D\u001F]")
def check_invalid_s(stin):
  if stin==None or stin=="":
    return False
  if _check_invalid_chars.search(stin)!=None: #stin.isidentifier()==False: or stin.isalnum()==False:
    return False
  return True


_check_invalid_name=re.compile("[,;+ %#`´\^\\\\]")
def check_invalid_name(stin):
#todo: remove user "bytes" from databases if exists, to prevent hacking attacks where bytes can't be removed
  if stin==None or type(stin)==bytes or stin=="" or stin=="bytes":
    return False
  if _check_invalid_name.search(stin)!=None or _check_invalid_chars.search(stin): #stin.isidentifier()==False: or stin.isalnum()==False:
    return False
  return True


def printdebug(inp):
  if debug_mode==True:
    pprint.pprint(inp,stream=sys.stderr)
    #print(inp,file=sys.stderr)
    if inp is Exception:
      traceback.print_tb(inp.__traceback__)

def printerror(inp):
  if show_error_mode==True:
    pprint.pprint(inp,stream=sys.stderr)
    #print(inp,file=sys.stderr)
    if inp is Exception:
      traceback.print_tb(inp.__traceback__)




def scn_check_return(_socket):
  if _socket.receive_one()=="success":
    return True
  else:
    for protcount in range(0,protcount_max):
      if _socket.is_end()==True:
        break
      printerror(_socket.receive_one())
    return False

class scnConnectException(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

class scnRejectException(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

class scnNoByteseq(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)
class scnReceiveError(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)


#a socket wrapper maybe used in future
class scn_socket(object):
  _buffer=""
  #_socket=None
  #is_end_state=False

  def __init__(self,_socket):
    self._socket=_socket
  def decode_command(self,minlength,maxlength):
    temp=self._buffer.split(sepc,1)
    if len(temp)==1 and len(temp[0])>=1 and temp[0][-1]==sepm:
      self.is_end_state=True
      self._buffer=""
      if len(temp[0][:-1])<minlength:
        raise(scnReceiveError("decode_command: Too short"))
      if len(temp[0][:-1])>maxlength:
        raise(scnReceiveError("decode_command: Too long"))
      return temp[0][:-1]
    #  printdebug("seperator not found")
    #  return None
    if len(temp)>1:
      self._buffer=temp[1]
    else:
      self._buffer=""
    if len(temp[0])<minlength:
      raise(scnReceiveError("decode_command: Too short"))
    if len(temp[0])>maxlength:
      raise(scnReceiveError("decode_command: Too long"))
    else:
      return temp[0]
  def load_socket(self):
    temp=None
    try:
      #cleanup stub data. No problem because "" must be in form ""sepc
      for protcount in range(0,protcount_max):
        temp1=self._socket.recv(buffersize)
        tmp_scn_format=struct.Struct(">"+str(len(temp1))+"s")
        temp=tmp_scn_format.unpack(temp1)[0].decode("utf-8").replace("\n","").replace("\0","")
        if temp!="":
          break
    except (BrokenPipeError,SSL.ZeroReturnError):
      raise(BrokenPipeError)
    except (socket.timeout, SSL.WantReadError):
      printdebug("Command: Timeout or SSL.WantReadError")
    #except (socket.ECONNRESET, socket.EPIPE):
    #  pass
      temp=None
    except Exception as e:
      printerror("Command: Unknown error while receiving")
      printerror(e)
      temp=None
    return temp

  def is_end(self):
    return self.is_end_state
  # 1 arg: set maxlength, 2 args: set minlength, maxlength
  
  def receive_one(self,minlength=max_cmd_size,maxlength=None):
    self.is_end_state=False
    if maxlength==None:
      maxlength=minlength
      minlength=0
    if maxlength>buffersize-1:
      printdebug("Receiving command longer than buffersize-1 is dangerous: use send_bytes and receive_bytes instead")
    if len(self._buffer)>1 and (self._buffer[-1]==sepm or self._buffer[-1]==sepc):
      return self.decode_command(minlength,maxlength)
    elif self._buffer==sepm or self._buffer==sepc:
      temp2=self.load_socket()
      if temp2==None:
        raise(scnReceiveError("Error: loading from socket failed"))
      self._buffer=temp2
      return self.decode_command(minlength,maxlength)
    else:
      temp2=self.load_socket()
      if temp2==None:
        raise(scnReceiveError("Error: loading from socket failed"))
      self._buffer+=temp2
      return self.decode_command(minlength,maxlength)

  #if no max size is specified, take _minsize as min max
  def receive_bytes(self,min_size,max_size=None):
    if self.receive_one()!="bytes":
      raise(scnNoByteseq("No \"bytes\" keyword"))
    try:
      _request_size=int(self.receive_one())
    except Exception as e:
      printerror("Bytesequence: Conversion into len (Int) failed")
      printerror(e)
      self.send("error"+sepc+"int conversion"+sepm)
      raise(scnNoByteseq("int convert"))
    if max_size==None and _request_size==min_size+1: #for sepc/sepm
      self.send("success"+sepm)
    elif min_size<=_request_size and _request_size<=max_size+1: #for sepc/sepm
      self.send("success"+sepm)
    else:
      printdebug(str(min_size)+","+str(max_size)+" ("+str(_request_size)+")")
      self.send("error"+sepc+"size"+sepm)
      raise(scnNoByteseq("size"))
    scn_format2=struct.Struct(">"+str(_request_size)+"s")
    temp=self._socket.recv(_request_size)
    temp=scn_format2.unpack(temp[0:_request_size])[0]
    if temp[-1]==sepm:
      self.is_end_state=True
    return temp[0:-1]
  def send(self,_string):
    temp=bytes(_string,"utf-8")
    tmp_scn_format=struct.Struct(">"+str(len(temp))+"s")
    temp=tmp_scn_format.pack(temp)
    self._socket.sendall(temp)

  def send_bytes(self,_byteseq,end=False):
    if end==True:
      _byteseq+=bytes(sepm,"utf8")
    else:
      _byteseq+=bytes(sepc,"utf8")
    tmp_scn_format=struct.Struct(">"+str(len(_byteseq))+"s")
    _byteseq=tmp_scn_format.pack(_byteseq)
    len_byte_seq=len(_byteseq)
    try:
      self.send("bytes"+sepc+str(len_byte_seq)+sepc)
      is_accepting=self.receive_one()
      if is_accepting=="success":
        self._socket.sendall(tmp_scn_format.pack(_byteseq))
      else:
        eerrtemp=is_accepting
        for protcount in range(0,protcount_max):
          if self.is_end()==True:
            break
          eerrtemp+=","+self.receive_one()
        raise(scnRejectException("reject:"+eerrtemp))
    except BrokenPipeError as e:
      printdebug("Bytesequence: BrokenPipe")
      raise(e)
  def close(self):
    self._socket.shutdown()



def generate_certs(_path,_passphrase=None):
  genproc=None
  if _passphrase==None:
    genproc=Popen(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:"+str(key_size), "-keyout",_path+".priv", "-out",_path+".pub"],stdin=PIPE,stdout=PIPE, stderr=PIPE,universal_newlines=True)
    _answer=genproc.communicate("IA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")
  else:
    genproc=Popen(["openssl", "req", "-x509", "-aes256", "-newkey", "rsa:"+str(key_size),"-keyout",_path+".priv", "-out",_path+".pub"], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    _answer=genproc.communicate(_passphrase.strip("\n")+"\n"+_passphrase.strip("\n")+"\nIA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")

  #printdebug(_answer[0])
  printerror(_answer[1])

def check_certs(_path,_passphrase=None):
  if os.path.exists(_path+".priv")==False or os.path.exists(_path+".pub")==False:
    return False
  _key=None
  with open(_path+".priv", 'r') as readin:
    if _passphrase==None:
      _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read())
    else:
      _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read(),_passphrase)
  if _key==None:
    return False

  if os.path.exists(_path+".pub")==True:
    is_ok=False
    with open(_path+".pub", 'r') as readin:
      try:
        _c=SSL.Context(SSL.TLSv1_2_METHOD)
        _c.use_privatekey(_key)
        _c.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,readin.read()))
        _c.check_privatekey()
        is_ok=True
      except Exception as e:
        printerror(e)
    if is_ok==True:
      return True
  return False

def init_config_folder(_dir):
  if os.path.exists(_dir)==False:
    os.makedirs(_dir,0o700)
  else:
    os.chmod(_dir,0o700)
    
  



class scn_base_base(object):
  name=""
  version=""
  priv_cert=None
  pub_cert=b"\0"
  
  def s_info(self,_socket):
    _socket.send("success"+sepc+self.name+sepc+str(self.version)+sepc+str(secret_size)+sepm)

  def s_get_cert(self,_socket):
    _socket.send("success"+sepc)
    _socket.send_bytes(self.pub_cert,True)



#service_types:
#  "admin": special service, not disclosed
#  "main": points to current used computer
#  "store": points to storage
#  "notify": points to primary message device
#  "callback": points to callbackserver
#tunnellist: uid:service:tunnel



#services in 
class scn_base_server(scn_base_base):
  scn_names=None #scn_name_list()
  special_services={}
  special_services_unauth={}
  tunnel={}
#priv
  def admin_auth(self, _name,_secret):
    if check_invalid_s(_name) or self.scn_names.length(_name)==0:
      return False
    return self.scn_names.get(_name).verify_secret("admin",_secret)

  
#admin
  def s_register_name(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    #TODO: check if is_end
    if check_invalid_name(_name)==False:
      _socket.send("error"+sepc+"invalid characters"+sepm)
      return
    if self.scn_names.get(_name)!=None:
      _socket.send("error"+sepc+"name exists already"+sepm)
      return
    temp=self.scn_names.create_name(_name,_secret)
    if temp==None:
      _socket.send("error"+sepc+"creation failed"+sepm)
      return
    _socket.send("success"+sepm)

#second level auth would be good as 30 days grace
  def s_delete_name(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    #TODO: check if is_end
    if self.admin_auth(_name,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if self.scn_names.del_name(_name)==True:
      _socket.send("success"+sepm)
      return
    else:
      _socket.send("error"+sepc+"deleting failed"+sepm)
      return

  def s_update_message(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.admin_auth(_name,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    _message=_socket.receive_bytes(0,max_message_length)
    if check_invalid_s(_message)==False:
      _socket.send("error"+sepc+"invalid chars"+sepm)
      return
    ob=self.scn_names.get(_name)
    #here some checks
    if ob!=None:
      if ob.set_message(_message)==True:
        socket.send("success"+sepm)
        return
      else:
        socket.send("error"+sepm)
        return
    else:
      socket.send("error"+sepm)
      return

#"admin" updates admin group
  def s_update_service(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.admin_auth(_name,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    #64 is the size of sha256 in hex, format sepc hash sepu name sepc ...
    _secrethashstring=str(_socket.receive_bytes(0, hash_hex_size*max_name_length*max_user_services+2*max_user_services), "utf8")
    if self.scn_names.length(_name)>=max_user_services+1:
      _socket.send("error"+sepc+"limit"+sepm)
      return
    if check_invalid_name(self.scn_names)==False:
      _socket.send("error"+sepc+"invalid character"+sepm)
      return
    temphashes=_secrethashstring.split(sepc)
    if len(temphashes)>max_service_nodes:
      _socket.send("error"+sepc+"limit"+sepm)
      return
    temp2=[]
    for count in range(0,len(temphashes)):
      _hash_name_split=temphashes[count].split(sepu)
      if len(_hash_name_split)==2 and check_hash(_hash_name_split[0])==True and check_invalid_name(_hash_name_split[1])==True:
        temp2+=[_hash_name_split,]
      elif len(_hash_name_split)==1 and check_hash(_hash_name_split[0])==True:
        temp2+=[(_hash_name_split[0],""),]
      else:
        _socket.send("error"+sepc+"invalid hash or name"+sepm)
        return
    
    if self.scn_names.get(_name).update_service(temp2)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)

  def s_delete_service(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.admin_auth(_name,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    _service=_socket.receive_one(min_name_length,max_name_length)
    if self.scn_names.get(_name).delete_service(_service)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
    
  def s_get_service_secrethash(self,_socket,_service):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.admin_auth(_name,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    temp=""
    for elem in self.scn_names.get(_name).get(_service):
      temp+=sepc+str(elem[0])+sepu+str(elem[3])
    _socket.send("success"+temp+sepm)

#normal

#priv
  def service_auth(self,_name, _service,_secret):
    if check_invalid_s(_service)==False or check_invalid_s(_service)==False:
      return False
    if _service=="admin" or self.scn_names.length(_name)==0 or \
       self.scn_names.get(_name).get(_service)==None or \
       not self.scn_names.verify_secret(_service,_secret):
      return False
    return True

#pub auth
#_socket.socket.getpeername()[1]] how to get port except by giving it
  def s_serve_service(self,_socket,_port,connect_type="ip"):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if _service in self.special_services or self.service_auth(_name,_service,_servicesecret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return

    if connect_type=="ip":
      _address=["ip",_socket.socket.getpeername()[0]+sepu+_port]
    elif connect_type=="wrap":
      _address=["wrap",_socket.socket.getpeername()[0]+sepu+_port]
    else:
      _socket.send("error"+sepm)
      return
    
    if len(_address!=2):
      _socket.send("error"+sepc+"address length"+sepm)
      return
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  def s_unserve_service(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if _service in self.special_services or self.service_auth(_name,_service,_servicesecret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    #check if end
  
    _address=["",""]
    
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  def s_update_secret(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.service_auth(_name,_service,_servicesecret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    try:
      _newsecret_hash=str(_socket.receive_bytes(hash_hex_size), "utf8")
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secrethash"+sepc+str(e)+sepm)
      return
    _newcert_hash=None
    if _socket.is_end()==False:
      try:
        _newcert_hash=str(_socket.receive_bytes(hash_hex_size), "utf8")
      except scnReceiveError as e:
        _socket.send("error"+sepc+"certhash"+sepc+str(e)+sepm)
        return
    if self.scn_names.get(_name).update_secret(_service,_servicesecret,_newsecret_hash,_newcert_hash)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepc+"update failed"+sepm)
      return


  def s_use_special_service_auth(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self.service_auth(_name,_service,_servicesecret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if _service not in self.special_services:
      _socket.send("error"+sepc+"specialservice not exist"+sepm)
      return
    _address=["special",""]
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      
      if _socket.is_end()==True:
        _socket.send("success"+sepm)
      self.special_services[_service](self,_socket,_name)
      
    else:
      _socket.send("error"+sepm)

#anonym,unauth
  def s_get_service(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    if _service=="admin":
      _socket.send("error"+sepc+"admin"+sepm)
    elif self.scn_names.length(_name)==0:
      _socket.send("error"+sepc+"not exists"+sepm)
    elif not self.scn_names.get(_name).length( _service)==0:
      _socket.send("error"+sepc+"service not exist"+sepm)
    else:
      temp=""
      for elem in self.scn_names.get(_name).get(_service):
        temp+=sepc+elem[1]+sepu+elem[2]
      _socket.send("success"+temp+sepm)


  def s_get_name_message(self,_socket,_name):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    if self.scn_names.length(_name)==0:
      _socket.send("error"+sepc+"not exists"+sepm)
    else:
      _socket.send("success"+sepc)
      _socket.send_bytes(self.scn_names.get(_name).get_message(),True)


  def s_use_special_service_unauth(self,_socket):
    try:
      _service=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"special service"+sepc+str(e)+sepm)
      return

    if _service not in self.special_services_unauth:
      _socket.send("error"+sepc+"not exist"+sepm)
      return
    if _socket.is_end()==True:
      _socket.send("success"+sepm)
    self.special_services_unauth[_service](self,_socket)
  def s_ping(self,_socket):
    _socket.send("success"+sepm)







#client receives:
#hello: servicename
#disconnected: reason
#service_wrap

#client get answer
#error,errormessage;
#success,commanddata (not for binary or free text);


class scn_base_client(scn_base_base):
  scn_servs=None
  scn_friends=None
  
  
  def c_update_service(self,_servername,_name,_service,_secrethashstring):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    _socket.send("update_service"+sepc+_name+sepc+_service)
    _socket.send_bytes(temp[3])
    _socket.send_bytes(_secrethashstring,True)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.close()
    return True
  
  def c_get_service_secrethash(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    _socket.send("get_service_secrethash"+sepc+_name+sepc+_service)
    _socket.send_bytes(temp[3],True)
    _node_list=[]
    if scn_check_return(_socket)==True:
      for protcount in range(0,protcount_max):
        temp = _socket.receive_one.split(sepu)
        if len(temp) == 1:
          temp=(temp[0],"")
        _node_list += [temp,]

    else:
      _node_list = None
    _socket.close()
    return _node_list

#pub
  def c_register_name(self,_servername,_name):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    _socket.send("register_name"+sepc+_name+sepc)
    _socket.send_bytes(_secret,True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      self.scn_servs.update_service(_servername,_name,"admin",_secret)
    return _server_response

  def c_delete_name(self,_servername,_name):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    _socket.send("delete_name"+sepc+_name+sepc)
    _socket.send_bytes(temp[3],_socket,True)
    _server_response=scn_check_return(_socket)
    if _server_response==True:
      self.scn_servs.delete_name(_name)
    _socket.close()
    return _server_response

  def c_update_name_message(self,_servername,_name,_message):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    _socket.send("update_message"+sepc+_name+sepc)
    _socket.send_bytes(temp[3],True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response

  def c_delete_service(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,_service)
    _socket.send("delete_service"+sepc+_name+sepc+_service+sepc,_socket)
    _socket.send_bytes(temp[3],_socket)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
  
  
  def c_unserve_service(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,_service)
    _socket.send("unserve"+sepc+_name+sepc+_service+sepc,_socket)
    _socket.send_bytes(temp[3],_socket,True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
    #temp=self.scn_servs.get_(_servername,_name,_servicename)

  def c_update_secret(self,_servername,_name,_service,_pub_cert=None):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    _socket.send("update_secret"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[3])
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _pub_cert==None:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest(),True)
    else:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest())
      _socket.send_bytes(hashlib.sha256(_pub_cert).hexdigest(),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      self.scn_servs.update_service(_servername,_name,_service,_secret)
    return _server_response

  #for special services like tunnels, returns socket
  def c_use_special_service_auth(self, _servername, _name, _service):
    _socket = scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername, _name, _service)
    _socket.send("use_special_service_auth"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[3],True)
    if scn_check_return(_socket):
      return _socket
    else:
      return None

  def c_get_service(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_service"+sepc+_name+sepc+_service+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      for protcount in range(0,protcount_max):
        _node_list += [_socket.receive_one(),]
    else:
      _node_list = None
    _socket.close()
    return _node_list

  
  def c_get_name_message(self,_servername,_name,_service):
    _socket = scn_socket(self.connect_to(_servername))
    _socket.send("get_name_message"+sepc+_name+sepc+_service+sepm)
    if scn_check_return(_socket) == True:
      _message = str(_socket.receive_bytes(0,max_message_length),"utf8")
    else:
      _message = None
    _socket.close()
    return _message


  #returns socket for use in other functions
  def c_use_special_service_unauth(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("use_special_service_unauth"+sepc+_name+sepc+_service+sepm)
    if scn_check_return(_socket) == True:
      return _socket
    else:
      _socket.close()
      return None

  def c_get_cert(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_cert"+sepm)
    _state=scn_check_return(_socket)
    if _state==False:
      return None
    _cert=_socket.receive_bytes(0,max_cert_size)
    return [_cert,]

  def c_info(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("info"+sepm)
    _state=scn_check_return(_socket)
    if _state==False:
      return None
    _servername=_socket.receive_one()
    _version=_socket.receive_one()
    _serversecretsize=_socket.receive_one()
    return [_servername,_version,_serversecretsize]





#priv

