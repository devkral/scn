

#LICENSE: my code: bsd 3-clauses, openssl: bsd 4-clauses


import re
#import pprint
#import traceback
import os
import os.path
import threading
import time
import logging

sepm="\x1D" #seperate messages (consist of commands)
sepc="\x1E" #seperate commands
sepu="\x1F" #seperate units (part of command, convention)




#import Enum from enum
#debug_mode, show_error_mode, 
from scn_config import min_name_length, max_name_length,secret_size,protcount_max,hash_hex_size
#, scn_cache_timeout


min_used_name=min(len("admin"),min_name_length)
max_used_name=max(len("admin"),max_name_length)

# from scn_config import scn_client_port

  


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
  if _check_invalid_chars_base.search(stin) is not None:
    return False
  return True

_check_invalid_chars_message=re.compile("[\0\x1A\x7F]")
def check_invalid_message(stin):
  if stin is None:
    return False
  if _check_invalid_chars_message.search(stin) is not None:
    return False
  return True

# default check for user entered names
_check_invalid_name=re.compile("[,; \\^\\\\]")
def check_invalid_name(stin):
  if stin is None or type(stin)==bytes or stin=="":
    return False
  if _check_invalid_name.search(stin) is not None or \
     _check_invalid_chars_base.search(stin) is not None or \
     _check_invalid_chars_user.search(stin) is not None:
     # or \
     #stin.strip(" ").rstrip(" ") =="admin"
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

#class TimeoutError(Exception):
#  pass



#def printdebug(inp):
#  if debug_mode==True:
#    #pprint.pprint(inp,stream=sys.stderr)
#    #print(inp,file=sys.stderr)
#    if isinstance(inp, scnException)==True:
#      print("Debug: "+type(inp).__name__,file=sys.stderr)
#      print(inp.args,file=sys.stderr)
#      #traceback.print_tb(inp.__traceback__)
#    elif isinstance(inp, Exception)==True:
#      print("Debug: "+type(inp).__name__,file=sys.stderr)
#      pprint.pprint(inp.args,stream=sys.stderr)
#      traceback.print_tb(inp.__traceback__)
#    else:
#      print("Debug: ", end="",file=sys.stderr )
#      pprint.pprint(inp,stream=sys.stderr)

#def printerror(inp):
#  if show_error_mode==True:
#    #pprint.pprint(inp,stream=sys.stderr)
#    #print(inp,file=sys.stderr)
#    if isinstance(inp, scnException)==True:
#      print("Error: "+type(inp).__name__,file=sys.stderr)
#      print(inp.args,file=sys.stderr)
#      traceback.print_tb(inp.__traceback__)
#    elif isinstance(inp, Exception)==True:
#      print("Error: "+type(inp).__name__,file=sys.stderr)
#      pprint.pprint(inp.args,stream=sys.stderr)
#      traceback.print_tb(inp.__traceback__)
#    else:
#      print("Error: ",end="",file=sys.stderr)
#      pprint.pprint(inp,stream=sys.stderr)

  
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
    logging.error(temp[:-2])
    return False

    


def init_config_folder(_dir):
  if os.path.exists(_dir)==False:
    os.makedirs(_dir,0o700)
  else:
    os.chmod(_dir,0o700)


class rwlock(object):
  readlock=None
  writelock=None
  _writes_passed=0
  def __init__(self):
    self.readlock=threading.Semaphore(1)
    self.writelock=threading.Event()
    self.writelock.clear()
  

  def readaccess(self,func):
    def tfunc(*args,**kwargs):
      try:
        self.readlock.acquire(False)
        self.writelock.wait()
        func(*args,**kwargs)
      except Exception:
        pass
      finally:
        self.readlock.release()
    return tfunc


  def writeaccess(self,func):
    def tfunc(*args,**kwargs):
      time.sleep(1)
      try:
        self.writelock.set()
        self.readlock.acquire(True)
        self._writes_passed+=1
        func(*args,**kwargs)
      except Exception:
        pass
      finally:
        self._writes_passed-=1
        self.readlock.release()
        if self._writes_passed==0:
          self.writelock.clear()
    return tfunc

class config_backend(object):
  lock=None
  def __init__(self):
    self.lock=rwlock()

    

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


#channels in
