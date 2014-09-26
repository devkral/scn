#! /usr/bin/env python3

#LICENSE: my code: bsd 3-clauses, openssl: bsd 4-clauses


import socket
import struct
import re
import sys
import pprint
import traceback
import os
import os.path
import hashlib
import time

from subprocess import Popen,PIPE

from OpenSSL import SSL,crypto




#import Enum from enum

from scn_config import debug_mode, show_error_mode, buffersize, max_cert_size, max_cmd_size, min_name_length, max_name_length,max_message_length, max_user_services, max_service_nodes, secret_size, key_size,protcount_max,hash_hex_size, scn_cache_timeout

# from scn_config import scn_client_port

sepm="\x1D" #seperate messages (consist of commands)
sepc="\x1E" #seperate commands
sepu="\x1F" #seperate units (part of command, convention)
  


def check_hash(_hashstr):
  if len(_hashstr)==hash_hex_size and all(c in "0123456789abcdefABCDEF" for c in _hashstr):
    return True
  return False
#check if invalid non blob (e.g. name, command)
_check_invalid_chars=re.compile("[\$\0'%\" \n\r\b\x1A\x7F"+sepm+sepc+sepu+"]")
def check_invalid_s(stin):
  if stin==None or stin=="":
    return False
  if _check_invalid_chars.search(stin)!=None:
    return False
  return True


_check_invalid_name=re.compile("[,; \^\\\\]")
def check_invalid_name(stin):
  if stin==None or type(stin)==bytes or stin=="":
    return False
  if _check_invalid_name.search(stin)!=None or _check_invalid_chars.search(stin):
    return False
  return True



class scnException(Exception):
  pass

class scnConnectException(scnException):
  pass
class scnRejectException(scnException):
  pass
class scnNoByteseq(scnException):
  pass
class scnReceiveError(scnException):
  pass


def printdebug(inp):
  if debug_mode==True:
    #pprint.pprint(inp,stream=sys.stderr)
    #print(inp,file=sys.stderr)
    if isinstance(inp, scnException)==True:
      print("Debug: "+type(inp).__name__,file=sys.stderr)
      print(inp.args,file=sys.stderr)
      #traceback.print_tb(inp.__traceback__)
    elif isinstance(inp, Exception)==True:
      print("Debug: "+type(inp).__name__,file=sys.stderr)
      pprint.pprint(inp.args,stream=sys.stderr)
      traceback.print_tb(inp.__traceback__)
    else:
      print("Debug: ", end="",file=sys.stderr )
      pprint.pprint(inp,stream=sys.stderr)

def printerror(inp):
  if show_error_mode==True:
    #pprint.pprint(inp,stream=sys.stderr)
    #print(inp,file=sys.stderr)
    if isinstance(inp, scnException)==True:
      print("Error: "+type(inp).__name__,file=sys.stderr)
      print(inp.args,file=sys.stderr)
      traceback.print_tb(inp.__traceback__)
    elif isinstance(inp, Exception)==True:
      print("Error: "+type(inp).__name__,file=sys.stderr)
      pprint.pprint(inp.args,stream=sys.stderr)
      traceback.print_tb(inp.__traceback__)
    else:
      print("Error: ",end="",file=sys.stderr)
      pprint.pprint(inp,stream=sys.stderr)

#not name saved with cert but name on server
def scn_verify_cert(_name,pub_cert,_certhash):
  temphash=hashlib.sha256(bytes(_name,"utf8"))
  temphash.update(pub_cert)
  if temphash.hexdigest()==_certhash:
    return True
  else:
    return False

def scn_check_return(_socket):
  temp=_socket.receive_one()
  if temp=="success":
    return True
  else:
    if temp=="error":
      temp=""
    else:
      temp="invalid("+temp+"): "
    for protcount in range(0,protcount_max):
      if _socket.is_end()==True:
        break
      temp2=_socket.receive_one()
      if temp2=="bytes":
        temp+="<"+temp2+", "
        temp+=_socket.receive_one()+">, "
        _socket.send("error"+sepc+"scn_check_return")
      else:
        temp+=temp2+", "
    printerror(temp[:-2])
    return False

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
      raise(BrokenPipeError())
    except (SSL.SysCallError) as e:
      if e.args[0]==104 or e.args[0]==-1:
        #"104: ECONNRESET, -1: Unexpected EOF"
        raise(BrokenPipeError())
      else:
        raise(e)
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
        raise(scnReceiveError("loading from socket failed"))
      self._buffer=temp2
      return self.decode_command(minlength,maxlength)
    else:
      temp2=self.load_socket()
      if temp2==None:
        raise(scnReceiveError("loading from socket failed"))
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
        reject_reason=is_accepting
        for protcount in range(0,protcount_max):
          if self.is_end()==True:
            break
          reject_reason+=","+self.receive_one()
        raise(scnRejectException("reject:"+reject_reason))
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
  if _answer[1]!="":
    printdebug(_answer[1])

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

  def pong(self,_socket):
    _socket.send("success"+sepm)
  def ping(self,_socket):
    _socket.send("pong"+sepm)
    return scn_check_return(_socket)
  

#service_types:
#  "admin": special service, not disclosed
#  "main": points to current used computer
#  "store": points to storage
#  "notify": points to primary message device
#  "special": group for using special_services
#tunnellist: uid:service:tunnel



#services in 
class scn_base_server(scn_base_base):
  scn_names=None #scn_name_list()
  scn_store=None #scn_ip_store()
  special_services={}
  special_services_unauth={}
  tunnel={}
  cache_name_list=None
#priv
  def _s_admin_auth(self, _socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return [None,None]
    if check_invalid_s(_name)==False or self.scn_names.length(_name)==0:
      _socket.send("error"+sepc+"name constraints"+sepm)
      return [None,None]
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return [None,None]
    if self.scn_names.get(_name).verify_secret("admin",_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return [None,None]
    return [_name,_secret]

  
#admin
  def s_register_name(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _secrethash=str(_socket.receive_bytes(hash_hex_size),"utf8")
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secrethash"+sepc+str(e)+sepm)
      return
    try:
      _certhash=str(_socket.receive_bytes(hash_hex_size),"utf8")
    except scnReceiveError as e:
      _socket.send("error"+sepc+"certhash"+sepc+str(e)+sepm)
      return
    #TODO: check if is_end
    if check_invalid_name(_name)==False or \
       check_hash(_secrethash)==False or \
       check_hash(_certhash)==False:
      _socket.send("error"+sepc+"invalid characters"+sepm)
      return
    if self.scn_names.get(_name)!=None:
      _socket.send("error"+sepc+"name exists already"+sepm)
      return
    temp=self.scn_names.create_name(_name,_secrethash,_certhash)
    if temp==None:
      _socket.send("error"+sepc+"creation failed"+sepm)
      return
    _socket.send("success"+sepm)

#second level auth would be good as 30 days grace
  def s_delete_name(self,_socket):
    _name,_secret=self._s_admin_auth(_socket)
    #TODO: check if is_end
    if _name==None:
      return
    if self.scn_names.del_name(_name)==True and self.scn_store.del_name(_name):
      _socket.send("success"+sepm)
      return
    else:
      _socket.send("error"+sepc+"deleting failed"+sepm)
      return

  def s_update_message(self,_socket):
    _name,_secret=self._s_admin_auth(_socket)
    if _name==None:
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

#"admin" updates admin group is_update True: updates, False adds
  def s_update_service_intern(self,_socket,is_update):

    _name,_secret=self._s_admin_auth(_socket)
    if _name==None:
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    _nameob=self.scn_names.get(_name)
    if is_update==False and (_nameob.get_service(_service)!=None):
      _socket.send("error"+sepc+"service exists"+sepm)
      return
    elif is_update==True and (_nameob.get_service(_service)==None):
      _socket.send("error"+sepc+"service not exists"+sepm)
      return
    else:
      _socket.send("success"+sepm)

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
    self.scn_store.del_service(_name,_service)
    temp2=[]
    for count in range(0,len(temphashes)):
      _hash_name_split=temphashes[count].split(sepu)
      if len(_hash_name_split)==3 and \
         check_invalid_name(_hash_name_split[0])==True and \
         check_hash(_hash_name_split[1])==True and \
         check_hash(_hash_name_split[2])==True:
        temp2+=[_hash_name_split,]
      elif len(_hash_name_split)==2 and \
           check_hash(_hash_name_split[0])==True and \
           check_hash(_hash_name_split[1])==True:
        temp2+=[("",_hash_name_split[0],_hash_name_split[1]),]
      else:
        _socket.send("error"+sepc+"invalid hash or name"+sepm)
        return
    
    if self.scn_names.get(_name).update_service(_service,temp2)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)

  def s_update_service(self,_socket):
    self.s_update_service_intern(_socket,True)

  def s_add_service(self,_socket):
    self.s_update_service_intern(_socket,False)

  def s_get_service_secrethash(self,_socket):
    _name,_secret=self._s_admin_auth(_socket)
    if _name==None:
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    temp=""
    for elem in self.scn_names.get(_name).get_service(_service):
      temp+=sepc+str(elem[0])+sepu+str(elem[3])
    _socket.send("success"+temp+sepm)

  def s_delete_service(self,_socket):
    _name,_secret=self._s_admin_auth(_socket)
    if _name==None:
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    
    if self.scn_names.get(_name).delete_service(_service)==True and \
    self.scn_store.del_service(_name,_service):
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
#normal

#priv
  def _s_service_auth(self,_socket):
    #_name, _service,_secret):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return [None,None,None]
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return [None,None,None]
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return [None,None,None]
    if check_invalid_s(_service)==False or check_invalid_s(_service)==False:
      return False
    if _service=="admin" or self.scn_names.length(_name)==0 or \
       self.scn_names.get(_name).get_service(_service)==None or \
       not self.scn_names.verify_secret(_service,_secret):
      _socket.send("error"+sepc+"auth failed"+sepm)      
      return [None,None,None]
    return [_name,_service,_secret]

#pub auth
#_socket.socket.getpeername()[1]] how to get port except by giving it
  def s_serve_service(self,_socket):
    _name,_service,_servicesecret=self._s_service_auth(_socket)
    if _name==None:
      return
    
    if _service in self.special_services:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    try:
      _addr_type=_socket.receive_one()
    except scnReceiveError as e:
      _socket.send("error"+sepc+"addr_type"+sepc+str(e)+sepm)
      return
    try:
      _addr=_socket.receive_one()
    except scnReceiveError as e:
      _socket.send("error"+sepc+"addr"+sepc+str(e)+sepm)
      return

    if _addr_type=="ip": #_addr=port
      _address=["ip",_socket.socket.getpeername()[0]+sepu+_addr]
    else:
      _socket.send("error"+sepm)
      return
    
    if self.scn_store.update(_address[0],_address[1],self.scn_names.get(_name).get_cert(hashlib.sha256(_servicesecret).hexdigest()))==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  def s_unserve_service(self,_socket):
    _name,_service,_servicesecret=self._s_service_auth(_socket)
    if _name==None:
      return
    if _service in self.special_services:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    #check if end
      
    if self.scn_store.del_node(_name,_service,hashlib.sha256(_servicesecret).hexdigest())==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  def s_del_serve(self,_socket):
    _name,_service,_servicesecret=self._s_service_auth(_socket)
    if _name==None:
      return
    #check if end
    if self.scn_names.get(_name).delete_secret(_service,_servicesecret)==False or \
    self.scn_store.del_node(_name,_service,hashlib.sha256(_servicesecret).hexdigest())==False:
      _socket.send("error"+sepm)
      return
    else:
      _socket.send("success"+sepm)
      


  def s_update_secret(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self._s_service_auth(_name,_service,_servicesecret)==False:
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

  # I'm not sure if this function is desireable; don't include it in available serveractions yet
  #issue: could be used for quick password checking
  def s_check_service_cred(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self._s_service_auth(_name,_service,_servicesecret)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)


  def s_use_special_service_auth(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    try:
      _servicesecret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return
    if self._s_service_auth(_name,_service,_servicesecret)==False and self._s_service_auth(_name,"special",_servicesecret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if _service not in self.special_services:
      _socket.send("error"+sepc+"specialservice not exist"+sepm)
      return
    if _socket.is_end()==True:
      _socket.send("success"+sepm)
      self.special_services[_service](self,_socket,_name)
    else:
      _socket.send("error"+sepc+"not end"+sepm)

#anonym,unauth
  def s_get_service(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    if _service=="admin":
      _socket.send("error"+sepc+"admin"+sepm)
    elif _service=="special":
      _socket.send("error"+sepc+"special"+sepm)
    elif self.scn_names.length(_name)==0:
      _socket.send("error"+sepc+"not exists"+sepm)
    elif not self.scn_names.get(_name).length( _service)==0:
      _socket.send("error"+sepc+"service not exist"+sepm)
    else:
      temp=""
      for elem in self.scn_store.get(_name,_service):
        temp+=sepc+elem[0]+sepu+elem[1]+sepu+elem[2] #addrtype, addr, _certhash
      _socket.send("success"+temp+sepm)

  def s_list_services(self,_socket):
    try:
      _name=_socket.receive_one(min_name_length,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    temp=""
    for elem in self.scn_names.get(_name).list_services():
      temp+=sepc+elem #name
    _socket.send("success"+temp+sepm)

#not threading safe
  def s_list_names(self,_socket):
    if self.cache_name_list==None or \
       self.cache_name_time>=time.time()+scn_cache_timeout:
      self.cache_name_time=time.time()
      self.cache_name_list=""
      for elem in self.scn_names.list_names():
        self.cache_name_list+=sepc+elem #name
    _socket.send("success"+self.cache_name_list+sepm)



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
      _service=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"special service"+sepc+str(e)+sepm)
      return

    if _service not in self.special_services_unauth:
      _socket.send("error"+sepc+"not exist"+sepm)
      return
    if _socket.is_end()==True:
      _socket.send("success"+sepm)
    self.special_services_unauth[_service](self,_socket)







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
  direct_list={}
  wrap_list={}

  def c_update_service(self,_servername,_name,_service,_secrethashstring):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    _socket.send("update_service"+sepc+_name+sepc)
    _socket.send_bytes(temp[2])
    _socket.send(_service+sepc)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.send_bytes(_secrethashstring,True)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.close()
    return True


  def c_add_service(self,_servername,_name,_service,_secrethashstring=None):
    _socket=scn_socket(self.connect_to(_servername))
    if _secrethashstring==None:
      _secret=os.urandom(secret_size)
      temphash=hashlib.sha256(bytes(_name,"utf8"))
      temphash.update(self.pub_cert)
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    if temp==None:
      printerror("Error: no admin rights")
      return False
    _socket.send("add_service"+sepc+_name+sepc)
    _socket.send_bytes(temp[2])
    _socket.send(_service+sepc)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _secrethashstring==None:
      _socket.send_bytes(bytes("self"+sepu+hashlib.sha256(_secret).hexdigest()+sepu+temphash.hexdigest(),"utf8"),True)
    else:
      _socket.send_bytes(_secrethashstring,True)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    #add to local serves
    _socket.close()
    return True
  
  def c_get_service_secrethash(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    _socket.send("get_service_secrethash"+sepc+_name)
    _socket.send_bytes(temp[2])
    _socket.send(_service+sepm)
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
    _socket.send_bytes(bytes(hashlib.sha256(_secret).hexdigest(),"utf8"))
    temphash=hashlib.sha256(bytes(_name,"utf8"))
    temphash.update(self.pub_cert)
    _socket.send_bytes(bytes(temphash.hexdigest(),"utf8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      return self.scn_servers.update_service(_servername,_name,"admin",_secret,False)
    return False

  def c_delete_name(self,_servername,_name):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    if temp==None:
      printerror("No admin permission")
      _socket.close()
      return
    _socket.send("delete_name"+sepc+_name+sepc)
    _socket.send_bytes(temp[2],_socket,True)
    _server_response=scn_check_return(_socket)
    if _server_response==True:
      self.scn_servers.delete_name(_name)
    _socket.close()
    return _server_response

  def c_update_name_message(self,_servername,_name,_message):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    _socket.send("update_message"+sepc+_name+sepc)
    _socket.send_bytes(temp[2],True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response

  def c_delete_service(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,"admin")
    _socket.send("delete_service"+sepc+_name+sepc)
    _socket.send_bytes(temp[2])
    _socket.send_bytes(_service+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
  
  
  def c_unserve_service(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,_service)
    _socket.send("unserve"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[2],_socket,True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
    #temp=self.scn_servers.get_(_servername,_name,_servicename)

  def c_update_secret(self,_servername,_name,_service,_pub_cert=None):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    temp=self.scn_servers.get_service(_servername,_name,_service)
    _socket.send("update_secret"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[2])
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _pub_cert==None:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest(),True)
    else:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest())
      temphash=hashlib.sha256(bytes(_name,"utf8"))
      _socket.send_bytes(temphash.update(_pub_cert).hexdigest(),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      self.scn_servers.update_service(_servername,_name,_service,_secret)
    return _server_response


  #for special services like tunnels, returns socket
  def c_use_special_service_auth(self, _servername, _name, _service):
    _socket = scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername, _name, _service)
    _socket.send("use_special_service_auth"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[2],True)
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
        _node_list += [_socket.receive_one().split(sepu),]
    else:
      _node_list = None
    _socket.close()
    return _node_list


  def c_list_names(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_names"+sepm)
    _name_list=[]
    if scn_check_return(_socket) == True:
      for protcount in range(0,protcount_max):
        _name_list += [_socket.receive_one(),]
    else:
      _name_list = None
    _socket.close()
    return _name_list

  def c_list_services(self,_servername,_name):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_services"+sepc+_name+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      for protcount in range(0,protcount_max):
        _node_list += [_socket.receive_one(),]
    else:
      _node_list = None
    _socket.close()
    return _node_list

  
  def c_get_name_message(self,_servername,_name):
    _socket = scn_socket(self.connect_to(_servername))
    _socket.send("get_name_message"+sepc+_name+sepm)
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

  def c_get_server_cert(self,_servername):
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

  #generate request for being added in service
  def c_create_serve(self,_servername,_name,_service):
    _secret=os.urandom(secret_size)
    if self.scn_servers.update_service(_servername,_name,_service,_secret,True)==False:
      return None
    return [_servername,_name,_service,hashlib.sha256(_secret).hexdigest()]

  def c_del_serve(self,_servername,_name,_service,force=False):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_service(_servername,_name,_service)
    _socket.send("del_serve"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[3],True)
    _server_response=scn_check_return(_socket)
    if _server_response==False:
      printerror("Error: deleting on server failed")
      if force==False:
        return False
    if self.scn_servers.del_service(_servername,_name,_service)==False:
      return False
    return True


  def c_serve_service(self,_servername,_name,_service,_addr_type,_addr):
    _socket=scn_socket(self.connect_to(_servername))
    tempservice=self.scn_servers.get_service(_servername,_name,_service)
    _socket.send("serve"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(tempservice[2])
    _socket.send(_addr_type+sepc+_addr+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response == True and tempservice[4] == 1:
      return self.scn_servers.update_service_pendingstate(_servername,_name,_service,False)
    else:
      return _server_response

  def s_hello(self,_socket):
    try:
      _reqservice=_socket.receive_one(1,max_name_length) #port or name
    except scnReceiveError as e:
      _socket.send("error"+sepc+"service"+sepc+str(e)+sepm)
      return
    if _reqservice in self.wrap_list:
      _socket.send("error"+sepc+"not implemented yet"+sepm)
      return
    elif _reqservice in self.direct_list:
      _socket.send("success"+sepc+"direct"+sepm)
      return
    else:
      _socket.send("error"+sepc+"not available"+sepm)
      return
  
  def c_hello(self,_servername,_name,identifier,_service="main"): #identifier: port or name
    temp=self.c_connect_to_node(_servername,_name,_service)
    if temp==None:
      return None
    _socket=scn_socket(temp[0])
    _socket.send("hello"+sepc+identifier+sepm)
    if scn_check_return(_socket)==True:
      _servicecontype=_socket.receive_one()
      _socket.close()
      return [temp[0],temp[1],temp[2],_servicecontype]
    else:
      _socket.close()
      return None


  def c_add_server(self,_url,_servername):
    _socket=scn_socket(self.connect_to_ip(_url))
    if self.scn_servers.get_node(_servername)!=None:
      printerror("Error: node exists already")
      _socket.close()
      return False
    
    _socket.send("get_cert"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return False
    _cert=_socket.receive_bytes(0,max_cert_size)
    _socket.close()
    if self.scn_servers.update_node(_servername,_url,_cert)==True:
      return True
    else:
      printdebug("node update failed")
      return False

  def c_update_server(self,_url,_servername): #, update_cert_hook):
    if self.scn_servers.get_node(_servername)==None:
      printerror("Error: Node doesn't exist")
      return False
    _socket=scn_socket(self.connect_to_ip(_url))
    #neccessary?
    #masquerade, nobody should know if this server is being added or updated
    #_socket.send("info"+sepm)
    #if scn_check_return(_socket) == False:
    #  _socket.close()
    #  return False
    #_socket.receive_one()
    #_socket.receive_one()#version
    #_socket.receive_one()#_serversecretsize
    #if _socket.is_end() == False:
    #  printerror("Error: is_end false before second command")
    #  _socket.close()
    #  return False

    _socket.send("get_cert"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return False
    _newcert=_socket.receive_bytes(0,max_cert_size)
    _socket.close()
    if _newcert!=self.scn_servers.get_node(_servername):
      printdebug("Certs missmatch, update because of missing hook")
    if self.scn_servers.update_node(_servername,_url,_newcert)==True:
      return True
    else:
      printdebug("node update failed")
      return False
    
  def c_delete_server(self,_servername):
    if self.scn_servers.del_node(_servername)==True:
      return True
      #return self.scn_friends.del_server_all(_nodename)
    else:
      printerror("node deletion failed")
      return False
