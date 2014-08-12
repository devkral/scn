#! /usr/bin/env python3

import socket
import struct
import re
import sys
import os
import os.path

from OpenSSL import SSL,crypto


#import Enum from enum

from scn_config import debug_mode, show_error_mode, buffersize, max_normal_size, protcount_max, min_name_length, max_name_length, max_user_services, max_service_nodes, key_size

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


def printdebug(string):
  if debug_mode==True:
    print(string,file=sys.stderr)

def printerror(string):
  if show_error_mode==True:
    print(string,file=sys.stderr)

scn_format=struct.Struct(">"+str(buffersize)+"s")

def scn_send(_string,_socket):
  temp=bytes(_string,"utf-8")
  start=0
  while start < len(temp):
    _socket.sendall(scn_format.pack(temp[start:start+buffersize]))
    start+=buffersize
  _socket.sendall(scn_format.pack(temp[start:start+buffersize-(len(temp)%buffersize)]))

def scn_send_bytes(_byteseq,_socket,end=False):
  len_byte_seq=len(_byteseq)
  _socket.sendall(scn_format.pack(b"bytes,"+len_byte_seq.to_bytes(len_byte_seq.bit_length()))) #after byteseq, no sepc
  is_accepting=_socket.recv(1)
  if is_accepting==b"y":
    temp_format_bytes=struct.Struct(">"+str(buffersize+1)+"s")
    if end==False:
      _socket.sendall(temp_format_bytes.pack(_byteseq+bytes(sepc)))
    else:
      _socket.sendall(temp_format_bytes.pack(_byteseq+bytes(sepm)))
    return True
  else:
    return False


def scn_check_return(reqreturn):
  temp=reqreturn.split(sepc,1)
  if temp[0]=="success":
    return True
  else:
    return False

def scn_receive(_socket,max_ob_size=max_normal_size):
  _buffer=""
  temp=[]
  protcount=0
  while protcount<protcount_max:
    if _buffer!="":
      _buffer=_buffer.replace("\n","").replace("\0","")
      if _buffer[-1]==sepc:
        temp+=_buffer.split(sepc)
        _buffer=""
      else:
        temp+=_buffer.split(sepc)[:-1]
        _buffer=_buffer.split(sepc)[-1]

    if len(temp)>=2 and temp[-2]=="bytes":
      try:
        _size=int(temp[-1])
      except Exception as e:
        printdebug("Int error")
        printdebug(e)
        return None
      try:
        if _size<max_ob_size:
          _socket.sendall(b"y")
          scn_format2=struct.Struct(">"+str(_size)+"s")
          temp2=_socket.recv(_size)
          
        if len(temp2)==_size:
          temp=temp[:-2]+[scn_format2.unpack(temp2)[0],]
        else:
          printerror("Bytesequence: Invalid size")
          return None
        checkif_sepm=_socket.recv(1)
        if checkif_sepm==bytes(sepm):
          return temp
        elif checkif_sepm==bytes(sepc):
          pass
        else:
          printdebug("Bytesequence: should be closed with either sepc or sepm")
        else:
          _socket.sendall(b"n")
       
      except socket.timeout or SSL.WantReadError:
        return None
      except Exception as e:
        printerror(e)
        return None
    
    if _buffer!="" and _buffer.find(sepm)!=-1:
      break

    try:
      temp3=_socket.recv(buffersize)
    except socket.timeout:
      return None
    except Exception as e:
      printerror(e)
      return None
    
    if len(temp3)==buffersize:
      _buffer+=scn_format.unpack(temp3)[0].decode("utf-8")
    else:
      printerror("Main: Invalid size")
      return None
  temp+=[_buffer.split(sepm,1)[0],] #sepm should be end, if not don't care
  return temp


def generate_certs(self,_path,_passphrase=None):
  _key = crypto.PKey()
  _key=RSA.generate(crypto.TYPE_RSA,key_size*8)
  privkey=None
  if _passphrase==None:
    privkey=crypto.dump_privatekey(crypto.FILETYPE_PEM,_key)
  else:
    #TODO: expose cipher choice
    privkey=crypto.dump_privatekey(crypto.FILETYPE_PEM,_key,"CAMELLIA256",passphrase)
#don't forget similar section in check_certs if updated
  _cert = crypto.X509()
  _cert.set_serial_number(0)
  #_cert.gmtime_adj_notBefore(notBefore)
  #_cert.gmtime_adj_notAfter(notAfter)
  _cert.set_issuer("")
  _cert.set_subject("")
  _cert.set_pubkey(_key)
  #TODO: expose hash choice
  _cert.sign(_key, "sha256")
  with open(_path+".priv", 'w') as writeout:
    writeout.write(privkey)
    os.chmod(_path+".priv",0o700)
  with open(_path+".pub", 'w') as writeout:
    writeout.write(crypto.dump_certificate(crypto.FILETYPE_PEM,_cert))


def check_certs(self,_path,_passphrase=None):
  if os.path.exists(_path+".priv")==False:
    return False
  if os.path.exists(_path+".pub")==False:
    printdebug("Publiccert doesn't exist. Generate new")
    success=False
    with open(_path+".priv", 'r') as readin:
      if _passphrase==None:
        _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read())
      else:
        _key=crypto.load_privatekey(crypto.FILETYPE_PEM,readin.read(),_passphrase)
      _cert = crypto.X509()
      _cert.set_serial_number(0)
      #_cert.gmtime_adj_notBefore(notBefore)
      #_cert.gmtime_adj_notAfter(notAfter)
      _cert.set_issuer("")
      _cert.set_subject("")
      _cert.set_pubkey(_key)
      with open(_path+".pub", 'w') as writeout:
        writeout.write(crypto.dump_certificate(crypto.FILETYPE_PEM,_cert))
        success=True
    return success
  return True





def init_config_folder(self,_dir):
  if os.path.exists(_dir)==False:
    os.mkdir(_dir,0o700)
  else:
    os.chmod(_dir,0o700)
    
  
  

  

#service_types:
#  "admin": special service, not disclosed
#  "main": points to current used computer
#  "store": points to storage
#  "notify": points to primary message device
#  "callback": points to callbackserver
#tunnellist: uid:service:tunnel



#services in 
class scn_base_server(object):
  scn_names=None #scn_name_list()
  special_services={}
  special_services_unauth={}
  name=""
  version=""
  priv_cert=None
  pub_cert=b"\0"
  tunnel={}
#priv
  def admin_auth(self, _name,_secret):
    if check_invalid_s(_name) or self.scn_names.length(_name)==0:
      return False
    return self.scn_names.get(_name).verify_secret("admin",_secret)

  
#admin
  def register_name(self,_socket,_name,_secret):
    if len(_name)<min_name_length or len(_name)>max_name_length:
      scn_send("error"+sepc+"length;",_socket)
      return
    if check_invalid_name(_name)==False:
      scn_send("error"+sepc+"invalid characters"+sepm,_socket)
      return
    temp=self.scn_names.create_name(_name,_secret)
    if temp==None:
      scn_send("error"+sepm,_socket)
      return
    scn_send("success"+sepm,_socket)

#second level auth would be good as 30 days grace
  def delete_name(self,_socket,_name,_secret):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    if self.scn_names.del_name(_name)==True:
      scn_send("success"+sepm,_socket)
      return
    else:
      scn_send("error"+sepc+"deleting failed"+sepm,_socket)
      return

  def update_cert(self,_socket,_name,_secret,_cert):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    ob=self.scn_names.get(_name)
    #here some checks
    if ob!=None:
      if ob.set_cert(_cert)==True:
        scn_send("success"+sepm,_socket)
        return
      else:
        scn_send("error"+sepm,_socket)
        return
    else:
      scn_send("error"+sepm,_socket)
      return
  def update_message(self,_socket,_name,_secret,_message):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth"+sepm,_socket)
      return
    if check_invalid_s(_message)==False:
      scn_send("error"+sepc+"invalid chars"+sepm,_socket)
      return
    ob=self.scn_names.get(_name)
    #here some checks
    if ob!=None:
      if ob.set_message(_message)==True:
        scn_send("success"+sepm,_socket)
        return
      else:
        scn_send("error"+sepm,_socket)
        return
    else:
      scn_send("error"+sepm,socket)
      return

#"admin" updates admin group
  def update_service(self,_socket,_name,_service,_secret,_secrethashstring,_namestring):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return

    if self.scn_names.length(_name)>max_user_services+1:
      scn_send("error"+sepc+"limit"+sepm,_socket)
      return
    if check_invalid_name(self.scn_names)==False:
      scn_send("error"+sepc+"invalid character"+sepm,_socket)
      return
    temphashes=_secrethashstring.split(sepc)
    tempnames=_namestring.split(sepc)
    if len(temphashes)>max_service_nodes:
      scn_send("error"+sepc+"limit"+sepm,_socket)
      return
    temp2=[]
    for count in range(0,len(temphashes)):
      if check_hash(temphashes[count])==True and check_invalid_name(tempnames[count])==True:
        temp2+=[[tempnames[count],temphashes[count]],]
      else:
        scn_send("error"+sepc+"invalid hash or name"+sepm,_socket)
        return
    
    if self.scn_names.get(_name).update_service(temp2)==True:
      scn_send("success"+sepm,_socket)
    else:
        scn_send(b"error"+sepm,_socket)

  def delete_service(self,_socket,_name,_service,_secret):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    
    if self.scn_names.get(_name).delete_service(_service)==True:
      scn_send("success"+sepm,_socket)
    else:
      scn_send(b"error"+sepm,_socket)
    
  def get_service_secrethash(self,_socket,_name,_secret,_service):
    if self.admin_auth(_name,_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    temp=""
    for elem in self.scn_names.get(_name).get(_service):
      temp+=sepc+str(elem[0])+sepu+str(elem[3])
    scn_send("success"+temp+sepm,_socket)



#normal

#priv
  def service_auth(self, _name,_service,_secret):
    if check_invalid_s(_service)==False or check_invalid_s(_service)==False:
      return False
    if _service=="admin" or self.scn_names.length(_name)==0 or self.scn_names.get(_name).get(_service)==None or not self.scn_names.verify_secret(_service,_secret):
      return False
    return True

#pub auth
#_socket.socket.getpeername()[1]] how to get port except by giving it
  def serve_service(self,_socket,_name,_service,_servicesecret,_port,connect_type="ip"):
    if _service in self.special_services or self.service_auth(_name,_service,_servicesecret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    if connect_type=="ip":
      _address=["ip",_socket.socket.getpeername()[0]+sepu+_port]
    elif connect_type=="wrap":
      _address=["wrap",_socket.socket.getpeername()[0]+sepu+_port]
    else:
      scn_send("error"+sepm,_socket)
      return
    
    if len(_address!=2):
      scn_send("error"+sepm,_socket)
      return
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      scn_send("success"+sepm,_socket)
    else:
      scn_send("error"+sepm,_socket)
      return

  def unserve_service(self,_socket,_name,_service,_servicesecret):
    if _service in self.special_services or self.service_auth(_name,_service,_servicesecret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    _address=["",""]
    
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      scn_send("success"+sepm,_socket)
    else:
      scn_send("error"+sepm,_socket)
      return

  def update_secret(self,_socket,_name,_service,_servicesecret,_newsecret):
    if self.service_auth(_name,_service,_servicesecret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    if self.scn_names.get(_name).update_secret(_service,_servicesecret,_newsecret)==True:
      scn_send("success"+sepm,_socket)
    else:
      scn_send("error"+sepc+"update failed"+sepm,_socket)
      return


  def use_special_service_auth(self,_socket,_name,_service,_servicesecret,*args):
    if self.service_auth(_name,_service,_servicesecret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    if _service not in self.special_services:
      scn_send("error"+sepc+"specialservice not exist"+sepm,_socket)
      return
    _address=["special",""]
    if self.scn_names.get(_name).auth(_service,_servicesecret,_address)==True:
      try:
        self.special_services[_service](self,_socket,_name,*args)
      except TypeError:
        scn_send("error"+sepc+"error invalid number args"+sepm,_socket)
    else:
      scn_send("error"+sepm,_socket)
      return

#anonym,unauth
  def get_service(self,_socket,_name,_service):
    if _service=="admin":
      scn_send("error"+sepc+"admin"+sepm,_socket)
    elif self.scn_names.length(_name)==0:
      scn_send("error"+sepc+"name"+sepm,_socket)
    elif not self.scn_names.get(_name).length( _service)==0:
      scn_send("error"+sepc+"service not exist"+sepm,_socket)
    else:
      temp=""
      for elem in self.scn_names.get(_name).get(_service):
        temp+=sepc+elem[1]+sepu+elem[2]
      scn_send("success"+temp+sepm,_socket)


  def get_name_message(self,_socket,_name):
    if self.scn_names.length(_name)==0:
      scn_send("error"+sepc+"name length"+sepm,_socket)
    else:
      scn_send("success"+sepc+self.scn_names.get(_name).get_message()+sepm,_socket)

  def get_name_cert(self,_socket,_name):
    if self.scn_names.length(_name)==0:
      scn_send("error"+sepc+"name length"+sepm,_socket)
    else:
      scn_send("success"+sepc,_socket)
      scn_send_bytes(self.scn_names.get(_name).get_cert(),_socket)
      scn_send(sepm,_socket)
#should be always available under info, because version important for communication
  def info(self,_socket):
    scn_send("success"+sepc+self.name+sepc+self.version+sepm,_socket)

  def get_server_cert(self,_socket):
    scn_send("success"+sepc+self.pub_cert+sepm,_socket)

  def use_special_service_unauth(self,_socket,_service,*args):
    if _service not in self.special_services_unauth:
      scn_send("error"+sepc+"specialservice not exist"+sepm,_socket)
      return
    try:
      self.special_services_unauth[_service](self,_socket,*args)
    except TypeError:
      scn_send("error"+sepc+"error invalid number args"+sepm,_socket)
  def ping(self,_socket):
    scn_send("pong"+sepm,_socket)



#client receives:
#hello: servicename
#disconnected: reason
#service_wrap

#client get answer
#error,errormessage;
#success,commanddata (not for binary or free text);


class scn_base_client(object):
  
  priv_cert=None
  pub_cert=b"\0"
  #init by __init__
  # servername: serverurl,[name,servicename,secret]
  scn_servs=None
  version=""
#priv

