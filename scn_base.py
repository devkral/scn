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
import threading

from subprocess import Popen,PIPE

from OpenSSL import SSL,crypto




#import Enum from enum

from scn_config import debug_mode, show_error_mode, buffersize, max_cert_size, max_cmd_size, min_name_length, max_name_length,max_message_length, max_user_channels, max_channel_nodes, secret_size, key_size,protcount_max,hash_hex_size
#, scn_cache_timeout

# from scn_config import scn_client_port

sepm="\x1D" #seperate messages (consist of commands)
sepc="\x1E" #seperate commands
sepu="\x1F" #seperate units (part of command, convention)
  


def check_hash(_hashstr):
  if len(_hashstr)==hash_hex_size and all(c in "0123456789abcdefABCDEF" for c in _hashstr):
    return True
  return False


_check_invalid_chars_base=re.compile("[\\$\0'%\"\n\r\t\b\x1A\x7F]")
# check if invalid non blob (e.g. domain, command)
_check_invalid_chars_user=re.compile("[ "+sepm+sepc+sepu+"]")
# default check for client sanitizion (is included in socket)
def check_invalid_s(stin):
  if stin is None or stin=="":
    return False
  if _check_invalid_chars_base.search(stin) is not None or \
     _check_invalid_chars_user.search(stin) is not None:
    return False
  return True

# default check for user entered names
_check_invalid_name=re.compile("[,; \\^\\\\]")
def check_invalid_name(stin):
  if stin is None or type(stin)==bytes or stin=="":
    return False
  if _check_invalid_name.search(stin) is not None or \
     _check_invalid_chars_base.search(stin) is not None or \
     _check_invalid_chars_user.search(stin) is not None or \
     stin.strip(" ").rstrip(" ") =="admin":
    return False
  return True

#time limiting function
def ltfunc(timelimit=2):
  def tfunc (func):
    def tfunc1(*args,**kwargs):
      __thread=threading.Thread(target=func,*args,**kwargs)
      __thread.daemon=False
      __thread.start()
      __thread.join(timelimit)
      if __thread.is_alive()==True:
        __thread.exit()
        return False
      else:
        return True
    return tfunc1
  return tfunc



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

def interact(inp):
  return input(inp)

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

#not domain saved with cert but domain on server
def scn_verify_cert(_domain,pub_cert,_certhash):
  temphash=hashlib.sha256(bytes(_domain,"utf8"))
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
  is_end_state=False
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
      if _check_invalid_chars_base.search(temp[0][:-1]) is not None:
        raise(scnReceiveError("decode_command: Contains invalid characters"))
      return temp[0][:-1]

    if len(temp)>1:
      self._buffer=temp[1]
    else:
      self._buffer=""
    if len(temp[0])<minlength:
      raise(scnReceiveError("decode_command: Too short"))
    if len(temp[0])>maxlength:
      raise(scnReceiveError("decode_command: Too long"))
    if _check_invalid_chars_base.search(temp[0][:-1]) is not None:
      raise(scnReceiveError("decode_command: Contains invalid characters"))
    return temp[0]
  
  #@ltfunc(10)
  def load_socket(self):
    temp=None
    try:
      #cleanup invalid data
      for protcount in range(0,protcount_max):
        temp1=self._socket.recv(buffersize)
        tmp_scn_format=struct.Struct(">"+str(len(temp1))+"s")
        #cleanup invalid signs
        temp=tmp_scn_format.unpack(temp1)[0].decode("utf-8").replace("\n","").replace("\0","")
        #if nothing is left continue cleaning up
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
    if maxlength is None:
      maxlength=minlength
      minlength=0
    if maxlength>buffersize-1:
      printdebug("Receiving command longer than buffersize-1 is dangerous: use send_bytes and receive_bytes instead")
    if len(self._buffer)>1 and (self._buffer[-1]==sepm or self._buffer[-1]==sepc):
      return self.decode_command(minlength,maxlength)
    elif self._buffer==sepm or self._buffer==sepc:
      temp2=self.load_socket()
      if temp2 is None:
        raise(scnReceiveError("loading from socket failed"))
      self._buffer=temp2
      return self.decode_command(minlength,maxlength)
    else:
      temp2=self.load_socket()
      if temp2 is None:
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
    if max_size is None and _request_size==min_size+1: #for sepc/sepm
      self.send("success"+sepm)
    elif min_size<=_request_size and _request_size<=max_size+1: #for sepc/sepm
      self.send("success"+sepm)
    else:
      printdebug(str(min_size)+","+str(max_size)+" ("+str(_request_size)+")")
      self.send("error"+sepc+"wrong size"+sepm)
      raise(scnNoByteseq("size"))
    scn_format2=struct.Struct(">"+str(_request_size)+"s")
    temp=self._socket.recv(_request_size)
    temp=bytes(scn_format2.unpack(temp[0:_request_size])[0])
    #[-1:] because of strange python behaviour.
    #it converts [:1] to int
    if temp[-1:]==bytes(sepm,"utf8"):
      self.is_end_state=True
    elif temp[-1:]==bytes(sepc,"utf8"):
      self.is_end_state=False
    else:
      self.send("error"+sepc+"wrong termination"+sepm)
      raise(scnNoByteseq("termination"))
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
    

def generate_certs(_path):
  genproc=None
  _passphrase=interact("(optional) Enter passphrase for encrypting key:\n")
  if _passphrase=="":
    genproc=Popen(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:"+str(key_size), "-keyout",_path+".priv", "-out",_path+".pub"],stdin=PIPE,stdout=PIPE, stderr=PIPE,universal_newlines=True)
    _answer=genproc.communicate("IA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")
  else:
    genproc=Popen(["openssl", "req", "-x509", "-aes256", "-newkey", "rsa:"+str(key_size),"-keyout",_path+".priv", "-out",_path+".pub"], stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    _answer=genproc.communicate(_passphrase.strip("\n")+"\n"+_passphrase.strip("\n")+"\nIA\n\n\n\nscn.nodes\n\nsecure communication nodes\n")

  #printdebug(_answer[0])
  if _answer[1]!="":
    printdebug(_answer[1])

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
  

#channel_types:
#  "admin": special channel, not disclosed
#  "main": points to current used computer
#  "store": points to storage
#  "notify": points to primary message device
#  "special": group for using special_channels <with auth to be implemented again>
#tunnellist: uid:channel:tunnel

min_used_name=min(len("admin"),min_name_length)
max_used_name=max(len("admin"),max_name_length)

#channels in
class scn_base_server(scn_base_base):
  scn_domains=None #scn_domain_list()
  scn_store=None #scn_ip_store()
  special_channels={}
  special_channels_unauth={}
  tunnel={}
  domain_list_cache=None
  domain_list_cond=None
  ## private 
  def __init__(self):
    self.domain_list_cond=threading.Event()

  def _s_admin_auth(self, _socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"domain"+sepc+str(e)+sepm)
      return [None,None]
    if check_invalid_name(_domain)==False or self.scn_domains.length(_domain)==0:
      _socket.send("error"+sepc+"name constraints"+sepm)
      return [None,None]
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return [None,None]
    if self.scn_domains.get(_domain).verify_secret("admin",_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return [None,None]
    return [_domain,_secret]

  # refresh cached domain name list, needed for a huge amount of domains
  def refresh_domain_list(self):
    while True:
      self.domain_list_cache=""
      temp=self.scn_domains.list_domains()
      if temp is not None:
        for elem in temp:
          self.domain_list_cache+=sepc+elem[0]
      self.domain_list_cond.clear()
      self.domain_list_cond.wait() #(scn_cache_timeout)
  
  ### domain section ###
  ## exposed
  #register domain and become admin
  #@scn_setup
  def s_register_domain(self,_socket):
    try:
      _domain=_socket.receive_one(min_name_length,max_name_length)
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
      print(_socket.is_end())
    except scnReceiveError as e:
      _socket.send("error"+sepc+"certhash"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    if check_invalid_name(_domain)==False or \
       check_hash(_secrethash)==False or \
       check_hash(_certhash)==False:
      _socket.send("error"+sepc+"invalid characters"+sepm)
      return
    if self.scn_domains.get(_domain) is not None:
      _socket.send("error"+sepc+"name exists already"+sepm)
      return
    temp=self.scn_domains.create_domain(_domain,_secrethash,_certhash)
    if temp is None:
      _socket.send("error"+sepc+"creation failed"+sepm)
      return
    self.domain_list_cond.set()
    _socket.send("success"+sepm)

  #second level defend would be good as 30 days grace
  #@scn_setup
  def s_delete_domain(self,_socket):
    _domain,_secret=self._s_admin_auth(_socket)
    if _domain is None:
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    if self.scn_domains.del_domain(_domain)==True:
      self.scn_store.del_domain(_domain)
      self.domain_list_cond.set()
      _socket.send("success"+sepm)
      return
    else:
      _socket.send("error"+sepc+"deleting failed"+sepm)
      return

  #update domain message or server message (=admin domain)
  #@scn_setup
  def s_update_message(self,_socket):
    _domain,_secret=self._s_admin_auth(_socket)
    if _domain is None:
      return
    _message=str(_socket.receive_bytes(0,max_message_length),"utf-8")
    if check_invalid_s(_message)==False:
      _socket.send("error"+sepc+"invalid chars"+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    ob=self.scn_domains.get(_domain)
    #here some checks
    if ob is not None:
      if ob.set_message(_message)==True:
        _socket.send("success"+sepm)
        return
      else:
        _socket.send("error"+sepm)
        return
    else:
      _socket.send("error"+sepm)
      return

  #"admin" updates admin group is_update True: updates, False adds
  #@scn_setup
  def s_update_channel_intern(self,_socket,is_update):
    _domain,_secret=self._s_admin_auth(_socket)
    if _domain is None:
      return
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    _domainob=self.scn_domains.get(_domain)
    if is_update==False and (_domainob.get_channel(_channel) is not None):
      _socket.send("error"+sepc+"channel exists"+sepm)
      return
    elif is_update==True and (_domainob.get_channel(_channel) is None):
      _socket.send("error"+sepc+"channel not exists"+sepm)
      return

    _socket.send("success"+sepm)

    #64 is the size of sha256 in hex, format sepc hash sepu domain sepc ...
    _secrethashstring=str(_socket.receive_bytes(0, hash_hex_size*max_name_length*max_user_channels+2*max_user_channels), "utf8")
    if _domainob.get_channel(_channel) is None and \
       self.scn_domains.length(_domain)>=max_user_channels+1:

      _socket.send("error"+sepc+"limit channels"+sepm)
      return
    temphashes=_secrethashstring.split(sepc)
    if len(temphashes)>max_channel_nodes:
      _socket.send("error"+sepc+"limit"+sepm)
      return
    self.scn_store.del_channel(_domain,_channel)
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
    
    if self.scn_domains.get(_domain).update_channel(_channel,temp2)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)

  #update existing channel
  #@scn_setup
  def s_update_channel(self,_socket):
    self.s_update_channel_intern(_socket,True)

  #add a channel if it doesn't exist
  #@scn_setup
  def s_add_channel(self,_socket):
    self.s_update_channel_intern(_socket,False)

  #get hashes of node secrets, needed for administration of nodes
  #@scn_setup
  def s_get_channel_secrethash(self,_socket):
    _domain,_secret=self._s_admin_auth(_socket)
    if _domain is None:
      return
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    temp=""
    for elem in self.scn_domains.get(_domain).get_channel(_channel):
      temp+=sepc+str(elem[0])+sepu+str(elem[2])
    _socket.send("success"+temp+sepm)

  #delete a channel 
  #@scn_setup
  def s_delete_channel(self,_socket):
    _domain,_secret=self._s_admin_auth(_socket)
    if _domain is None:
      return
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return
    if _channel=="admin":
      _socket.send("error"+sepc+"can't delete admin"+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    if self.scn_domains.get(_domain).delete_channel(_channel)==True:
      self.scn_store.del_channel(_domain,_channel)
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)

  ### node section ###
  ##private
  # node authentification
  def _s_channel_auth(self,_socket):
    #_domain, _channel,_secret):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return [None,None,None]
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return [None,None,None]
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secret"+sepc+str(e)+sepm)
      return [None,None,None]
    if check_invalid_name(_domain)==False or check_invalid_name(_channel)==False:
      return [None,None,None]
    if _channel=="admin" or self.scn_domains.length(_domain)==0 or \
       self.scn_domains.get(_domain).get_channel(_channel) is None or \
       not self.scn_domains.verify_secret(_channel,_secret):
      _socket.send("error"+sepc+"auth failed"+sepm)      
      return [None,None,None]
    return [_domain,_channel,_secret]

  ##exposed

  # start: serving as node in a channel
  #@scn_setup
  def s_serve_channel(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return
    
    if _channel in self.special_channels:
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
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return

    if _addr_type=="ip": #_addr=port
      _address=["ip",_socket.socket.getpeername()[0]+sepu+_addr]
    else:
      _socket.send("error"+sepm)
      return
    
    if self.scn_store.update(_address[0],_address[1],self.scn_domains.get(_domain).get_cert(hashlib.sha256(_channelsecret).hexdigest()))==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  # stop: serving as node in a channel
  #@scn_setup
  def s_unserve_channel(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return
    if _channel in self.special_channels:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    if self.scn_store.del_server(_domain,_channel,hashlib.sha256(_channelsecret).hexdigest())==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepm)
      return

  # stop being node in a channel
  #@scn_setup
  def s_del_serve(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    if self.scn_domains.get(_domain).delete_secret(_channel,_channelsecret)==False or \
    self.scn_store.del_server(_domain,_channel,hashlib.sha256(_channelsecret).hexdigest())==False:
      _socket.send("error"+sepm)
      return
    else:
      _socket.send("success"+sepm)

  # update node secret
  #@scn_setup
  def s_update_secret(self,_socket):
    #wrong
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
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
    if self.scn_domains.get(_domain).update_secret(_channel,_channelsecret,_newsecret_hash,_newcert_hash)==True:
      _socket.send("success"+sepm)
    else:
      _socket.send("error"+sepc+"update failed"+sepm)
      return

  ### anonym section ###
  #no authentification/registration needed

  # check if domain exists
  #@scn_setup
  def s_check_domain(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    if self.scn_domains.get(_domain) is None:
      _socket.send("success"+sepc+"false"+sepm)
    else:
      _socket.send("success"+sepc+"true"+sepm)

  # get nodenames and certs of nodes in a channel
  #@scn_setup
  def s_get_channel_nodes(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return

    if self.scn_domains.length(_domain)==0:
      _socket.send("error"+sepc+"domain not exists"+sepm)
      return
    elif self.scn_domains.get(_domain).get_channel( _channel) is None:
      _socket.send("error"+sepc+"channel not exist"+sepm)
      return
    temp=""
    if self.scn_domains.get(_domain).get_channel(_channel) is not None:

      for elem in self.scn_domains.get(_domain).get_channel(_channel):
        temp+=sepc+elem[1]+sepu+elem[3] #name,hashed_pubcert
    _socket.send("success"+temp+sepm)

  # get addresses and certs of nodes in a channel
  #@scn_setup
  def s_get_channel_addr(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"channel"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return

    if _domain=="admin" or _domain=="special":
      _socket.send("error"+sepc+"special"+sepm)
      return
    elif self.scn_domains.length(_domain)==0:
      _socket.send("error"+sepc+"domain not exists"+sepm)
      return
    elif self.scn_domains.get(_domain).get_channel( _channel) is None:
      _socket.send("error"+sepc+"channel not exist"+sepm)
      return
    elif self.scn_store.get(_domain,_channel) is None:
      _socket.send("error"+sepc+"channel has no active nodes"+sepm)
      return

    temp=""
    if self.scn_store.get(_domain,_channel) is not None:
      for elem in self.scn_store.get(_domain,_channel):
        temp+=sepc+elem[0]+sepu+elem[1]+sepu+elem[2] #addrtype, addr, _certhash
    _socket.send("success"+temp+sepm)


  # list channels of a domain
  #@scn_setup
  def s_list_channels(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    tempdomain=self.scn_domains.get(_domain)
    if tempdomain is None:
      _socket.send("error"+sepc+"domain"+sepm)
      return
    tempcont=tempdomain.list_channels()
    if tempcont is None:
      _socket.send("error"+sepc+"channel"+sepm)
      return
    temp=""
    for elem in tempcont:
      temp+=sepc+elem[0] #name
    _socket.send("success"+temp+sepm)

  # list domains
  #@scn_setup
  def s_list_domains(self,_socket):
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    #domainnames must be refreshed by a seperate thread because too much traffic elsewise
    #self.domain_list_cache begins with a sepc
    if self.domain_list_cache is not None:
      _socket.send("success"+self.domain_list_cache+sepm)
    else:
      _socket.send("error"+sepc+"domain_list_cache empty"+sepm)

  # get message of domain, in case of "admin" server message
  #@scn_setup
  def s_get_domain_message(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"name"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    if self.scn_domains.get(_domain) is None:
      _socket.send("error"+sepc+"not exists"+sepm)
    else:
      temp=self.scn_domains.get(_domain).get_message()
      _socket.send("success"+sepc)
      if temp is None:
        _socket.send_bytes(b"",True)
      else:
        _socket.send_bytes(bytes(temp,encoding="utf8"),True)

  #server services, renamed and added later, don't use it
  def s_use_special_channel_unauth(self,_socket):
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError as e:
      _socket.send("error"+sepc+"special channel"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return

    if _channel not in self.special_channels_unauth:
      _socket.send("error"+sepc+"not exist"+sepm)
      return
    if _socket.is_end()==True:
      _socket.send("success"+sepm)
    self.special_channels_unauth[_channel](self,_socket)







#client receives:
#hello: channelname
#disconnected: reason
#channel_wrap

#client get answer
#error,errormessage;
#success,commanddata (not for binary or free text);


class scn_base_client(scn_base_base):
  scn_servers=None
  scn_friends=None
  direct_list={}
  wrap_list={}

  #@scn_setup
  def c_update_channel(self,_servername,_domain,_channel,_secrethashstring):
    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("Error: no admin permission")
      return False
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("update_channel"+sepc+_domain+sepc)
    _socket.send_bytes(temp[2])
    _socket.send(_channel+sepc)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.send_bytes(_secrethashstring,True)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.close()
    return True

  #@scn_setup
  def c_add_channel(self,_servername,_domain,_channel,_secrethashstring=None):
    if _secrethashstring is None:
      _secret=os.urandom(secret_size)
      temphash=hashlib.sha256(bytes(_domain,"utf8"))
      temphash.update(self.pub_cert)
    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("Error: no admin permission")
      return False
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("add_channel"+sepc+_domain+sepc)
    _socket.send_bytes(temp[2])
    _socket.send(_channel+sepc)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _secrethashstring is None:
      _socket.send_bytes(bytes("self"+sepu+hashlib.sha256(_secret).hexdigest()+sepu+temphash.hexdigest(),"utf8"),True)
    else:
      _socket.send_bytes(_secrethashstring,True)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    #add to local serves
    _socket.close()
    return True
  
  #@scn_setup
  def c_get_channel_secrethash(self,_servername,_domain,_channel):
    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("Error: no admin permission")
      return False
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_secrethash"+sepc+_domain)
    _socket.send_bytes(temp[2])
    _socket.send(_channel+sepm)
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
  #@scn_setup
  def c_register_domain(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    _socket.send("register_domain"+sepc+_domain+sepc)
    _socket.send_bytes(bytes(hashlib.sha256(_secret).hexdigest(),"utf8"))
    temphash=hashlib.sha256(bytes(_domain,"utf8"))
    temphash.update(self.pub_cert)
    _socket.send_bytes(bytes(temphash.hexdigest(),"utf8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      return self.scn_servers.update_channel(_servername,_domain,"admin",_secret,False)
    return False

  #@scn_setup
  def c_delete_domain(self,_servername,_domain):
    if _domain=="admin":
      printerror("Undeleteable specialdomain admin")
      return False

    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("No admin permission")
      return False
    
    if self.c_check_domain(_servername,_domain)==False:
      self.scn_servers.del_domain(_servername,_domain)
      return True

    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("delete_domain"+sepc+_domain+sepc)
    _socket.send_bytes(temp[2],True)
    _server_response=scn_check_return(_socket)
    if _server_response==True:
      self.scn_servers.del_domain(_servername,_domain)
    _socket.close()
    return _server_response

  #@scn_setup
  def c_update_message(self,_servername,_domain,_message):
    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("No admin permission")
      return False
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("update_message"+sepc+_domain+sepc)
    _socket.send_bytes(temp[2])
    _socket.send_bytes(bytes(_message,"utf-8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response

  #@scn_setup
  def c_delete_channel(self,_servername,_domain,_channel):
    if _channel=="admin":
      printerror("Undeleteable specialchannel admin")
      return False
    
    temp=self.scn_servers.get_channel(_servername,_domain,"admin")
    if temp is None:
      printerror("No admin permission")
      return False
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("delete_channel"+sepc+_domain+sepc)
    _socket.send_bytes(temp[2])
    _socket.send(_channel+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
  
  #@scn_setup
  def c_unserve_channel(self,_servername,_domain,_channel):
    temp=self.scn_servers.get_channel(_servername,_domain,_channel)
    if temp is None:
      printerror("Can't unserve without a secret")
      return False
    
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("unserve"+sepc+_domain+sepc+_channel+sepc)
    _socket.send_bytes(temp[2],True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
    #temp=self.scn_servers.get_(_servername,_domain,_channelname)

  #@scn_setup
  def c_update_secret(self,_servername,_domain,_channel,_pub_cert=None):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    temp=self.scn_servers.get_channel(_servername,_domain,_channel)
    if temp is None:
      printerror("Can't update secret without a secret")
      return False
    _socket.send("update_secret"+sepc+_domain+sepc+_channel+sepc)
    _socket.send_bytes(temp[2])
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _pub_cert is None:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest(),True)
    else:
      _socket.send_bytes(hashlib.sha256(_secret).hexdigest())
      temphash=hashlib.sha256(bytes(_domain,"utf8"))
      _socket.send_bytes(temphash.update(_pub_cert).hexdigest(),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      self.scn_servers.update_channel(_servername,_domain,_channel,_secret)
    return _server_response

  
  #@scn_setup
  def c_get_channel_nodes(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_nodes"+sepc+_domain+sepc+_channel+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      #TODO: get max_node information from server
      for protcount in range(0,max_channel_nodes):
        if _socket.is_end()==True:
          break
        
        temp=_socket.receive_one(hash_hex_size+max_cmd_size).split(sepu)
        if len(temp)!=2:
          printdebug("invalid node object parsed")
          continue
        _node_list += [temp,]
    else:
      _node_list = None
    _socket.close()
    return _node_list

  #@scn_setup
  def c_get_channel_addr(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_addr"+sepc+_domain+sepc+_channel+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      #TODO: get max_node  information from server
      for protcount in range(0,max_channel_nodes):
        if _socket.is_end()==True:
          break
        temp=_socket.receive_one().split(sepu)
        if len(temp)!=3:
          printdebug("invalid node addr object parsed")
          continue
        _node_list += [temp,]
    else:
      _node_list = None
    _socket.close()
    return _node_list

  #@scn_setup
  def c_list_domains(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_domains"+sepm)
    _domain_list=[]
    if scn_check_return(_socket) == True:
      if _socket.is_end()==False: #security against malformed requests
        for protcount in range(0,protcount_max):
          _domain_list += [_socket.receive_one(),]
          if _socket.is_end()==True:
            break
    else:
      _domain_list = None
    _socket.close()
    return _domain_list

  #@scn_setup
  def c_list_channels(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_channels"+sepc+_domain+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      if _socket.is_end()==False: #security against malformed requests
        for protcount in range(0,protcount_max):
          _node_list += [_socket.receive_one(),]
          if _socket.is_end()==True:
            break
    else:
      _node_list = None
    _socket.close()
    return _node_list
  
  #@scn_setup
  def c_get_domain_message(self,_servername,_domain):
    _socket = scn_socket(self.connect_to(_servername))
    _socket.send("get_domain_message"+sepc+_domain+sepm)
    if scn_check_return(_socket) == True:
      _message = str(_socket.receive_bytes(0,max_message_length),"utf8")
    else:
      _message = None
    _socket.close()
    return _message
  
  #@scn_setup
  def c_get_server_message(self,_servername):
    return self.c_get_domain_message(_servername,"admin")

  #@scn_setup
  def c_get_server_cert(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_cert"+sepm)
    _state=scn_check_return(_socket)
    if _state==False:
      return None
    _cert=_socket.receive_bytes(0,max_cert_size)
    _socket.close()
    return [_cert,]

  #@scn_setup
  def c_info(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("info"+sepm)
    _state=scn_check_return(_socket)
    if _state==False:
      return None
    _servername=_socket.receive_one()
    _version=_socket.receive_one()
    _serversecretsize=_socket.receive_one()
    _socket.close()
    return [_servername,_version,_serversecretsize]

  
  def c_check_domain(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("check_domain"+sepc+_domain+sepm)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    if _socket.receive_one()=="true":
      _socket.close()
      return True
    else:
      _socket.close()
      return False
  
  #generate request for being added in channel
  #@scn_setup
  def c_create_serve(self,_servername,_domain,_channel):
    _secret=os.urandom(secret_size)
    if self.scn_servers.update_channel(_servername,_domain,_channel,_secret,True)==False:
      return None
    return [_servername,_domain,_channel,hashlib.sha256(_secret).hexdigest()]

  #@scn_setup
  def c_del_serve(self,_servername,_domain,_channel,force=False):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servers.get_channel(_servername,_domain,_channel)
    _socket.send("del_serve"+sepc+_domain+sepc+_channel+sepc)
    _socket.send_bytes(temp[3],True)
    _server_response=scn_check_return(_socket)
    if _server_response==False:
      printerror("Error: deleting on server failed")
      if force==False:
        return False
    if self.scn_servers.del_channel(_servername,_domain,_channel)==False:
      return False
    return True

  def c_serve_channel(self,_servername,_domain,_channel,_addr_type,_addr):
    _socket=scn_socket(self.connect_to(_servername))
    tempchannel=self.scn_servers.get_channel(_servername,_domain,_channel)
    _socket.send("serve"+sepc+_domain+sepc+_channel+sepc)
    _socket.send_bytes(tempchannel[2])
    _socket.send(_addr_type+sepc+_addr+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response == True and tempchannel[4] == 1:
      return self.scn_servers.update_channel_pendingstate(_servername,_domain,_channel,False)
    else:
      return _server_response

  #@scn_setup
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
    
  #@scn_setup
  def c_hello(self,_servername,_domain,identifier,_channel="main"): #identifier: port or name
    temp=self.c_connect_to_node(_servername,_domain,_channel)
    if temp is None:
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
  #returns socket for use in other functions
  def c_use_special_channel_unauth(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("use_special_channel_unauth"+sepc+_domain+sepc+_channel+sepm)
    if scn_check_return(_socket) == True:
      return _socket
    else:
      _socket.close()
      return None
  #@scn_setup
  def c_expose(self,addr_method,addr,identifier): #identifier is either port num or name
    pass
  
  #@scn_setup
  def c_unexpose(self,identifier): #identifier is either port num or name
    pass

  #@scn_setup
  def c_add_server(self,_servername,_url,_certname=None):
    _socket=scn_socket(self.connect_to_ip(_url))
    if _socket is None:
      printerror("Error: connection failed")
      return False
    
    _socket.send("get_cert"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return False
    _cert=_socket.receive_bytes(0,max_cert_size)
    _socket.close()
    if self.scn_servers.add_server(_servername,_url,_cert,_certname)==True:
      return True
    else:
      printdebug("server creation failed")
      return False

  #@scn_setup
  def c_update_server(self,_servername,_url): #, update_cert_hook):
    
    if self.scn_servers.get_server(_servername) is None:
      printerror("Error: server doesn't exist")
      return False
    _socket=scn_socket(self.connect_to_ip(_url))
    if _socket is None:
      printerror("Error: connection failed")
      return False
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
    if _newcert!=self.scn_servers.get_server(_servername)[1]:
      printdebug("Certs missmatch, update because of missing hook")
    if self.scn_servers.update_server(_servername,_url,_newcert)==True:
      return True
    else:
      printdebug("server update failed")
      return False

  #@scn_setup
  def c_delete_server(self,_servername):
    if self.scn_servers.del_server(_servername)==True:
      return True
      #return self.scn_friends.del_server_all(_servername)
    else:
      printerror("server deletion failed")
      return False
