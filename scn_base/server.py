
import threading
import hashlib

from scn_base._base import scn_base_base
from scn_base._base import sepm,sepc,sepu,min_used_name,max_used_name
from scn_base._base import check_hash,check_invalid_message,check_invalid_name
from scn_base._base import scnReceiveError


#from scn_base._base import scn_check_return
#from scn_base._socket import scn_socket

#from scn_base._socket import scn_socket


from scn_config import max_message_length,secret_size,hash_hex_size
from scn_config import min_name_length,max_name_length,max_user_channels,max_channel_nodes

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
    _socket.send("success"+sepm)
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
      _socket.send("error"+sepc+"name"+sepm)
      return
    try:
      _secrethash=str(_socket.receive_bytes(hash_hex_size),"utf8")
    except scnReceiveError as e:
      _socket.send("error"+sepc+"secrethash"+sepm)
      return
    try:
      _certhash=str(_socket.receive_bytes(hash_hex_size),"utf8")
    except scnReceiveError as e:
      _socket.send("error"+sepc+"certhash"+sepc+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    if _domain.strip(" ").rstrip(" ") =="admin":
      _socket.send("error"+sepc+"admin"+sepm)
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
    if check_invalid_message(_message)==False:
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
    
    _domainob=self.scn_domains.get(_domain)
    if is_update==False and _domainob.get_channel(_channel) is not None:
      _socket.send("error"+sepc+"channel exist"+sepm)
      return
    elif is_update==False and _channel=="admin":
      _socket.send("error"+sepc+"adminchannel"+sepm)
      return
    elif is_update==True and _domainob.get_channel(_channel) is None:
      _socket.send("error"+sepc+"channel not exist"+sepm)
      return

    _socket.send("success"+sepm)

    #64 is the size of sha256 in hex, format sepc name sepu secrethash sepu certhash sepc ...
    _secrethashstring=str(_socket.receive_bytes(0, hash_hex_size*max_name_length*max_user_channels+2*max_user_channels), "utf8")

    if _domainob.get_channel(_channel) is None and \
       self.scn_domains.length(_domain)>=max_user_channels+1:
      _socket.send("error"+sepc+"limit channels"+sepm)
      return
    
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
    
    temphashes=_secrethashstring.split(sepc)
    if len(temphashes)>max_channel_nodes:
      _socket.send("error"+sepc+"limit nodes"+sepm)
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
      temp+=sepc+str(elem[1])+sepu+str(elem[2])+sepu+str(elem[3])
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
      _socket.send("error"+sepc+"try delete admin"+sepm)
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
    except scnReceiveError:
      _socket.send("error"+sepc+"name"+sepm)
      return [None,None,None]
    try:
      _channel=_socket.receive_one(1,max_name_length)
    except scnReceiveError:
      _socket.send("error"+sepc+"channel"+sepm)
      return [None,None,None]
    try:
      _secret=_socket.receive_bytes(0,secret_size)
    except scnReceiveError:
      _socket.send("error"+sepc+"secret"+sepm)
      return [None,None,None]
    if check_invalid_name(_domain)==False:
      _socket.send("error"+sepc+"invalid domain characters"+sepm)
      return [None,None,None]
    if check_invalid_name(_channel)==False:
      _socket.send("error"+sepc+"invalid channel characters"+sepm)
      return [None,None,None]
    
    temp=self.scn_domains.get(_domain)
    if temp is None:
      _socket.send("error"+sepc+"domain not exist"+sepm)
      return [None,None,None]

    if temp.verify_secret(_channel,_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)      
      return [None,None,None]
    _socket.send("success"+sepm)
    return [_domain,_channel,_secret]

  ##exposed

  def s_check_perm(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return
    _socket.send("success"+sepm)
  
  # start: serving as node in a channel
  #@scn_setup
  def s_serve_channel(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return

    if _channel=="admin":
      _socket.send("error"+sepc+"admin"+sepm)
      return
    
    if _channel in self.special_channels:
      _socket.send("error"+sepc+"special"+sepm)
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
    self.scn_store.del_node(_domain,_channel,hashlib.sha256(_channelsecret).hexdigest())==False:
      _socket.send("error"+sepm)
      return
    else:
      _socket.send("success"+sepm)

  # update node secret
  #@scn_setup
  def s_update_secret(self,_socket):
    _domain,_channel,_channelsecret=self._s_channel_auth(_socket)
    if _domain is None:
      return
    try:
      _newsecret_hash=str(_socket.receive_bytes(hash_hex_size), "utf8")
    except scnReceiveError:
      _socket.send("error"+sepc+"secrethash"+sepm)
      return
    _newcert_hash=None
    if _socket.is_end()==False:
      try:
        _newcert_hash=str(_socket.receive_bytes(hash_hex_size), "utf8")
      except scnReceiveError as e:
        _socket.send("error"+sepc+"certhash"+sepm)
        return
      if _socket.is_end()==False:
        _socket.send("error"+sepc+"command not terminated"+sepm)
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

  # returns amount of channels within a domain
  def s_length_domain(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+str(e)+sepm)
      return
    if _socket.is_end()==False:
        _socket.send("error"+sepc+"command not terminated"+sepm)
        return
    tlength=self.scn_domains.length(_domain)
    _socket.send("success"+sepc+str(tlength)+sepm)

  # returns amount of nodes within a channel
  def s_length_channel(self,_socket):
    try:
      _domain=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+str(e)+sepm)
      return
    try:
      _channel=_socket.receive_one(min_used_name,max_used_name)
    except scnReceiveError as e:
      _socket.send("error"+str(e)+sepm)
      return
    if _socket.is_end()==False:
      _socket.send("error"+sepc+"command not terminated"+sepm)
      return
      
    tlength=self.scn_domains.get(_domain).length(_channel)
    _socket.send("success"+sepc+str(tlength)+sepm)
    
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
      try:
        _nodeid=_socket.receive_one(1,max_name_length)
      except scnReceiveError as e:
        _socket.send("error"+sepc+"nodeid"+sepc+str(e)+sepm)
        return
      if _socket.is_end()==False:
        _socket.send("error"+sepc+"command not terminated"+sepm)
        return
    else:
      _nodeid=None

    if self.scn_domains.length(_domain)==0:
      _socket.send("error"+sepc+"domain not exist"+sepm)
      return
    templ=self.scn_domains.get(_domain).get_channel( _channel,_nodeid)
    if templ is None:
      _socket.send("error"+sepc+"channel or nodeid not exist"+sepm)
      return
    temp=""
    for elem in templ:
      #nodeid,nodename,hashed_secret,hashed_pub_cert
      temp+=sepc+elem[1]+sepu+elem[3] # name,hashed_pubcert 
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
      try:
        _nodeid=_socket.receive_one(1,max_name_length)
      except scnReceiveError as e:
        _socket.send("error"+sepc+"nodeid"+sepc+str(e)+sepm)
        return
      if _socket.is_end()==False:
        _socket.send("error"+sepc+"command not terminated"+sepm)
        return
    else:
      _nodeid=None

    if _domain=="admin" or _domain=="special":
      _socket.send("error"+sepc+"special"+sepm)
      return
    elif self.scn_domains.length(_domain)==0:
      _socket.send("error"+sepc+"domain not exist"+sepm)
      return
    elif self.scn_domains.get(_domain).get_channel( _channel) is None:
      _socket.send("error"+sepc+"channel not exist"+sepm)
      return
    templ=self.scn_store.get(_domain,_channel,_nodeid)
    if templ is None:
      _socket.send("error"+sepc+"channel or nodeid not active"+sepm)
      return
    temp=""
    for elem in templ:
      temp+=sepc+elem[1]+sepu+elem[2]+sepu+elem[3] # addrtype, addr, certhash
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
    

  # list channels
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
      
    temp=""
    tempdomain=self.scn_domains.get(_domain)
    if tempdomain is None:
      _socket.send("error"+sepc+"domain not exist"+sepm)
      return
    tempcont=tempdomain.list_channels()
    if tempcont is None:
      _socket.send("error"+sepc+"channel not exist"+sepm)
      return
    for elem in tempcont:
      temp+=sepc+elem[0] #name
    _socket.send("success"+temp+sepm) # list with domain names

    
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
      _socket.send("error"+sepc+"domain not exist"+sepm)
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


