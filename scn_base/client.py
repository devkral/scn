
import os
import hashlib
import logging


#from scn_base._base import *
from scn_base._base import sepm,sepc,sepu
from scn_base._base import scn_base_base
from scn_base._base import scn_check_return
from scn_base._base import scnReceiveError

from scn_base._socket import scn_socket
from scn_base._crypto import scn_gen_ncert

from scn_config import max_name_length,max_message_length
from scn_config import hash_hex_size,max_cmd_size,max_cert_size,secret_size
from scn_config import protcount_max,max_channel_nodes

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
  #_write_channel=False for admin auth
  #return None if false else get_channel info
  def _c_channel_auth(self,_socket, _servername, _domain, _channel, _write_channel=True):
    _tchannelauth=self.scn_servers.get_channel(_servername,_domain,_channel)
    if _tchannelauth is None:
      return None
    chwrite=_domain+sepc
    if _write_channel==True:
      chwrite+=_channel+sepc
    _socket.send(chwrite)
    _socket.send_bytes(_tchannelauth[2])
    if scn_check_return(_socket)==False:
      return None
    return _socket,_tchannelauth
  
  def _c_admin_auth(self,_socket,_servername,_domain):
    return self._c_channel_auth(_socket,_servername,_domain,"admin",False)
    
    
#pub
  def c_update_channel(self,_servername,_domain,_channel,_secrethashstring):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("update_channel"+sepc)
    temp=self._c_admin_auth(_socket,_servername,_domain)
    if temp is None:
      return False
    _socket.send(_channel+sepc)
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.send_bytes(bytes(_secrethashstring,"utf8"),True)
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
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("add_channel"+sepc)
    temp=self._c_admin_auth(_socket,_servername,_domain)
    if temp is None:
      return False
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
    self.scn_servers.add_serve(_servername,_domain,_channel,_secret, "ip")
    self.scn_servers.update_serve_pendingstate(_servername,_domain,_channel)
    #add to local serves
    _socket.close()
    return True
  
  #@scn_setup
  def c_get_channel_secrethash(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_secrethash"+sepc)
    temp=self._c_admin_auth(_socket,_servername,_domain)
    if temp is None:
      return False
    _socket.send(_channel+sepm)
    _node_list=[]
    if scn_check_return(_socket)==True:
      for protcount in range(0,protcount_max):
        if _socket.is_end()==True:
          break
        temp = _socket.receive_one(2*hash_hex_size, 2*hash_hex_size+max_name_length).split(sepu)
        if len(temp) == 1:
          temp=("",temp[0])
        _node_list += [temp,]

    else:
      _node_list = None
    _socket.close()
    return _node_list


  #@scn_setup
  def c_register_domain(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    _socket.send("register_domain"+sepc+_domain+sepc)
    _socket.send_bytes(bytes(hashlib.sha256(_secret).hexdigest(),"utf8"))
    _socket.send_bytes(bytes(scn_gen_ncert(_domain,self.pub_cert),"utf8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      return self.scn_servers.add_serve(_servername,_domain,"admin",_secret,False)
    return False

  #@scn_setup
  def c_delete_domain(self,_servername,_domain):
    if _domain=="admin":
      logging.error("Undeleteable specialdomain admin")
      return False

    
    if self.c_check_domain(_servername,_domain)==False:
      self.scn_servers.del_domain(_servername,_domain)
      return True

    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("delete_domain"+sepc)
    temp=self._c_admin_auth(_socket,_domain)
    if temp is None:
      return False
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    self.scn_servers.del_domain(_servername,_domain)
    _socket.close()
    return True
    
  #@scn_setup
  def c_update_message(self,_servername,_domain,_message):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("update_message"+sepc)
    temp=self._c_admin_auth(_socket,_servername,_domain)
    if temp is None:
      return False
    _socket.send_bytes(bytes(_message,"utf-8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response

  #@scn_setup
  def c_delete_channel(self,_servername,_domain,_channel):
    if _channel=="admin":
      logging.error("Undeleteable specialchannel admin")
      return False
    
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("delete_channel"+sepc)
    temp=self._c_admin_auth(_socket,_servername,_domain)
    if temp is None:
      return False
    _socket.send(_channel+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response
  
  #@scn_setup
  def c_unserve_channel(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("unserve"+sepc)
    temp=self._c_channel_auth(_socket,_servername,_domain,_channel)
    if temp is None:
      return False
    if scn_check_return(_socket)==False:
      _socket.close()
      return False
    _socket.close()
    return True
    #temp=self.scn_servers.get_(_servername,_domain,_channelname)

  #@scn_setup
  def c_update_secret(self,_servername,_domain,_channel,_pub_cert=None):
    _socket=scn_socket(self.connect_to(_servername))
    _secret=os.urandom(secret_size)
    temp=self.scn_servers.get_channel(_servername,_domain,_channel)
    if temp is None:
      logging.error("Can't update secret without an old secret")
      return False
    _socket.send("update_secret"+sepc)
    temp=self._c_channel_auth(_socket,_servername,_domain,_channel)
    if temp is None:
      return False
    if _pub_cert is None:
      _socket.send_bytes(bytes(hashlib.sha256(_secret).hexdigest(),"utf8"),True)
    else:
      _socket.send_bytes(bytes(hashlib.sha256(_secret).hexdigest(),"utf8"))
      _socket.send_bytes(bytes(scn_gen_ncert(_domain,_pub_cert),"utf8"),True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==True:
      self.scn_servers.update_serve_secret(_servername,_domain,_channel,_secret)
    return _server_response

  
  #@scn_setup
  def c_get_channel_nodes(self,_servername,_domain,_channel,_nodeid=None):
    if _nodeid==None or type(_nodeid).__name__!='int':
      _nodeid=""
    else:
      _nodeid=sepc+str(_nodeid)
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_nodes"+sepc+_domain+sepc+_channel+_nodeid+sepm)
    _node_list=[]
    if scn_check_return(_socket) == True:
      #TODO: get max_node information from server
      for protcount in range(0,max_channel_nodes):
        if _socket.is_end()==True:
          break
        
        temp=_socket.receive_one(hash_hex_size+max_cmd_size).split(sepu)
        if len(temp)!=2:
          logging.debug("invalid node object parsed")
          continue
        _node_list += [temp,]
    else:
      _node_list = None
    _socket.close()
    return _node_list # nodeid,nodename,hashed_secret,hashed_pub_cert

  #@scn_setup
  def c_get_channel_addr(self,_servername,_domain,_channel,_nodeid=None):
    if _nodeid==None or type(_nodeid).__name__!='int':
      _nodeid=""
    else:
      _nodeid=sepc+str(_nodeid)
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("get_channel_addr"+sepc+_domain+sepc+_channel+_nodeid+sepm)
    
    _node_list=[]
    if scn_check_return(_socket) == True:
      #TODO: get max_node  information from server
      for protcount in range(0,max_channel_nodes):
        if _socket.is_end()==True:
          break
        temp=_socket.receive_one().split(sepu)
        if len(temp)!=3:
          logging.debug("invalid node addr object parsed")
          continue
        _node_list += [temp,]
    else:
      _node_list = None
    _socket.close()
    return _node_list # 

  # list channels
  #@scn_setup
  def c_list_channels(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_channels"+sepc+_domain+sepm)
    _tlist=[]
    if scn_check_return(_socket) == True:
      if _socket.is_end()==False: #security against malformed requests
        if _domain is None:
          for protcount in range(0,protcount_max):
            _tlist += [_socket.receive_one(),]
            if _socket.is_end()==True:
              break
        else:
          for protcount in range(0,protcount_max):
            _tlist += [_socket.receive_one(),]
            if _socket.is_end()==True:
              break
      else:
        _tlist = None
    _socket.close()
    return _tlist

  # list domains 
  #@scn_setup
  def c_list_domains(self,_servername):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("list_domains"+sepm)
    _tlist=[]
    if scn_check_return(_socket) == True:
      if _socket.is_end()==False: #security against malformed requests
        for protcount in range(0,protcount_max*10): #could be much bigger
          _tlist += [_socket.receive_one(),]
          if _socket.is_end()==True:
            break
      else:
        _tlist = None
    _socket.close()
    return _tlist

  
  
  # return count of channels with no channel arg,
  # elsewise the count of nodes
  #@scn_setup
  def c_length_domain(self,_servername,_domain):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("length_domain"+sepc+_domain+sepm)
    if scn_check_return(_socket) == True:
      return int(_socket.receive_one())
    else:
      return None
  
  # return count of channels with no channel arg,
  # elsewise the count of nodes
  #@scn_setup
  def c_length_channel(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("length_channel"+sepc+_domain+sepc+_channel+sepm)
    if scn_check_return(_socket) == True:
      return int(_socket.receive_one())
    else:
      return None
    
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
    if self.scn_servers.add_serve(_servername,_domain,_channel,_secret,True)==False:
      return None
    return [_servername,_domain,_channel,hashlib.sha256(_secret).hexdigest()]

  #@scn_setup
  def c_del_serve(self,_servername,_domain,_channel,force=False):
    temp=self.scn_servers.get_channel(_servername,_domain,_channel)
    if temp is None:
      logging.error("not node of channel")
      return False
    if _channel=="admin" and temp[4]==False: # if is not pending
      logging.error("revoking node rights as admin")
      return False
    
    _socket=scn_socket(self.connect_to(_servername))  
    _socket.send("del_serve"+sepc+_domain+sepc+_channel+sepc)
    _socket.send_bytes(temp[2],True)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response==False and temp[4]==False: # if is not pending
      logging.error("deleting on server failed")
      if force==False:
        return False
    if self.scn_servers.del_channel(_servername,_domain,_channel)==False:
      return False
    return True

  def c_serve_channel(self,_servername,_domain,_channel,_addr_type,_addr):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("serve"+sepc)
    tempchannel=self._c_channel_auth(_socket,_servername,_domain,_channel)
    if tempchannel is None:
      return False
    _socket.send(_addr_type+sepc+_addr+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    if _server_response == True and bool(tempchannel[3]) == True:
      return self.scn_servers.update_serve_pendingstate(_servername,_domain,_channel,False)
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
      logging.error("Error: connection failed")
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
      logging.debug("server creation failed")
      return False

  #@scn_setup
  def c_update_server(self,_servername,_url): #, update_cert_hook):
    
    if self.scn_servers.get_server(_servername) is None:
      logging.error("Error: server doesn't exist")
      return False
    _socket=scn_socket(self.connect_to_ip(_url))
    if _socket is None:
      logging.error("Error: connection failed")
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
    #  logging.error("Error: is_end false before second command")
    #  _socket.close()
    #  return False

    _socket.send("get_cert"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return False
    _newcert=_socket.receive_bytes(0,max_cert_size)
    _socket.close()
    if _newcert!=self.scn_servers.get_server(_servername)[1]:
      logging.debug("Certs missmatch, update because of missing hook")
    if self.scn_servers.update_server(_servername,_url,_newcert)==True:
      return True
    else:
      logging.debug("server update failed")
      return False

  #@scn_setup
  def c_delete_server(self,_servername):
    if self.scn_servers.del_server(_servername)==True:
      return True
      #return self.scn_friends.del_server_all(_servername)
    else:
      logging.error("server deletion failed")
      return False
  def c_check_perm(self,_servername,_domain,_channel):
    _socket=scn_socket(self.connect_to(_servername))
    _socket.send("check_perm"+sepc)
    tempchannel=self._c_channel_auth(_socket,_servername,_domain,_channel)
    if tempchannel is None:
      return False
    _socket.close()
    return True
  
  def c_update_pending(self,_servername,_domain,_channel):
    result=not self.c_check_perm(_servername,_domain,_channel)
    self.scn_servers.update_serve_pendingstate(_servername,_domain,_channel,result)
    return result
    
