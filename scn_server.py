#! /usr/bin/env python3


import signal
import sys
import socketserver
import socket
import threading
import logging
#import time

from OpenSSL import SSL,crypto

from scn_base import sepm,sepc #,sepu
from scn_base import scn_base_server,scn_base_base,scn_socket,init_config_folder,check_certs,generate_certs,interact

from scn_config import scn_host,scn_server_port,default_config_folder
#,scn_cache_timeout


from backend.sqlite.server import scn_ip_store,scn_domain_list_sqlite


class scn_server(scn_base_server):
  is_active=True
  server_context=None
  config_path=""
  actions={"register_domain": scn_base_server.s_register_domain,
           "delete_domain": scn_base_server.s_delete_domain,
           "update_message": scn_base_server.s_update_message,
           "add_channel": scn_base_server.s_add_channel,
           "update_channel": scn_base_server.s_update_channel,
           "delete_channel":scn_base_server.s_delete_channel,
           "get_channel_secrethash": scn_base_server.s_get_channel_secrethash,
           "get_channel_addr": scn_base_server.s_get_channel_addr,
           "get_channel_nodes": scn_base_server.s_get_channel_nodes,
           "check_perm": scn_base_server.s_check_perm,
           "serve": scn_base_server.s_serve_channel,
           "unserve": scn_base_server.s_unserve_channel,
           "del_serve": scn_base_server.s_del_serve,
           "update_secret": scn_base_server.s_update_secret,
           #"use_special_channel_auth": scn_base_server.s_use_special_channel_auth,
           "use_special_channel_unauth":scn_base_server.s_use_special_channel_unauth,
           "get_domain_message":scn_base_server.s_get_domain_message,
           "check_domain": scn_base_server.s_check_domain,
           "list_domains": scn_base_server.s_list_domains,
           "list_channels": scn_base_server.s_list_channels,
           "length_domain": scn_base_server.s_length_domain,
           "length_channel": scn_base_server.s_length_channel,
           "get_cert":scn_base_base.s_get_cert,
           "info":scn_base_base.s_info,
           "pong":scn_base_base.pong}

  callback={}

  def __init__(self,_config_path,_name):
    scn_base_server.__init__(self)
    self.version="1"
    self.name=_name
    self.config_path=_config_path
    init_config_folder(self.config_path)
    if check_certs(self.config_path+"scn_server_cert")==False:
      logging.debug("Certificate(s) not found. Generate new...")
      generate_certs(self.config_path+"scn_server_cert")
      logging.debug("Certificate generation complete")
    with open(self.config_path+"scn_server_cert"+".priv", 'rb') as readinprivkey:
      self.priv_cert=readinprivkey.read()
    with open(self.config_path+"scn_server_cert"+".pub", 'rb') as readinpubkey:
      self.pub_cert=readinpubkey.read()
    self.scn_domains=scn_domain_list_sqlite(self.config_path+"scn_server_domain_db")
    self.scn_store=scn_ip_store(self.config_path+"scn_server_pers_id_db")
    if self.scn_domains.get("admin") is None:
      #fixme: create working acc
      self.scn_domains.create_domain("admin",0,0)
    #self.special_channels={"retrieve_callback": self.retrieve_callback,"auth_callback": self.auth_callback}
    #self.special_channels_unauth={"test":self.s_info ,"callback":self.callback}
    self.refresh_domains_thread=threading.Thread(target=self.refresh_domain_list)
    self.refresh_domains_thread.daemon = True
    self.refresh_domains_thread.start()
    logging.debug("Server init finished")

"""
  def callback(self,_socket,_name,_store_name):
    if self.scn_names.contains(_name)==False:
      _socket.send("error"+sepc+"name not exists"+sepm)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("ip",str(_socket.getpeername()[0])+sepu+str(_socket.getpeername()[1])),]
    _socket.send( "success"+sepm)
  def tunnel_callback(self,_socket,_name,_store_name,_tunnelnumber):
    if self.scn_names.contains(_name)==False:
      _socket.send("error"+sepc+"name not exists"+sepm)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("tunnel",_tunnelnumber),]
    _socket.send("success"+sepm)

  def auth_callback(self,_socket,_name,_store_name,_secret):
    if self.scn_names.contains(_name)==False or \
 self.channel_auth(_store_name,"callback",_secret)==False \
or self.scn_names.contains(_store_name)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("name",_store_name),]
    _socket.send("success"+sepm)
    
  def retrieve_callback(self,_socket,_name,_secret):
    if self.scn_names.contains(_name)==False or self.channel_auth(_name,"callback",_secret)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    temp=""
    for elem in self.callback[_name]:
      temp+=sepc+elem[0]+sepu+elem[1]
    _socket.send("success"+temp+sepm)
    return """


class scn_server_handler(socketserver.BaseRequestHandler):
  linkback=None

  def handle(self):
    self.request.setblocking(True)
    sc=scn_socket(self.request)
    while True:
      try:
        temp=sc.receive_one()
        if temp is None:
          sc.send("error"+sepc+"no input"+sepm)
          break
        elif temp in self.linkback.actions:
          self.linkback.actions[temp](self.linkback,sc)
        else:
          sc.send("error"+sepc+temp+sepc+" no such function"+sepm)
      except BrokenPipeError:
        logging.debug("Socket closed") 
        break
      except SSL.SysCallError as e:
        if e.args[0]==104 or e.args[0]==-1:
          #"104: ECONNRESET, -1: Unexpected EOF"
          logging.debug("Socket closed")
        else:
          logging.error(e)
        break
      except Exception as e:
        logging.error(e)
        break

#socketserver.ThreadingMixIn, 
class scn_sock_server(socketserver.TCPServer):
  linkback=None
  def __init__(self, server_address, HandlerClass,_linkback):
    socketserver.BaseServer.__init__(self, server_address, HandlerClass)
    self.linkback=_linkback
    def interact_wrap():
      return interact("Please enter passphrase:\n")
    
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    temp_context.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM,self.linkback.priv_cert,interact_wrap))
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,self.linkback.pub_cert))
    self.socket = SSL.Connection(temp_context,socket.socket(self.address_family, self.socket_type))
    #self.socket.set_accept_state()
    self.server_bind()
    self.server_activate()


  def shutdown_request(self, request):
    if request is None:
      return
    try:
      # explicitly shutdown.  socket.close() merely releases
      # the socket and waits for GC to perform the actual close.
      request.shutdown() # shutdown of sslsocketwrapper
      request.sock_shutdown(socket.SHUT_RDWR) # hard shutdown of underlying socket
    except (OSError):
      pass # some platforms may raise ENOTCONN here
    except Exception as e:
      logging.error("Exception while shutdown")
      logging.error(e)
    self.close_request(request)

  def close_request(self,request):
    if request is None:
      return
    try:
      request.close()
    except Exception as e:
      logging.error(e)

server=None

def signal_handler(signal, frame):
  #rec_pre.is_active=False
  #rec.is_active=False
#  server.shutdown()
  sys.exit(0)
if __name__ == "__main__":
  logging.basicConfig()
  rec_pre = scn_server(default_config_folder,scn_host+"_scn")
  rec = scn_server_handler
  rec.linkback=rec_pre
  
  # Create the server, binding to localhost on port 9999
  server = scn_sock_server((scn_host, scn_server_port), rec,rec_pre) 
  signal.signal(signal.SIGINT, signal_handler)
  # Activate the server; this will keep running until you
  # interrupt the program with Ctrl-C
  
  #server_thread = threading.Thread(target=server.serve_forever)
  # Exit the server thread when the main thread terminates
  #server_thread.daemon = True
  #server_thread.start()
  #rec_pre.handle_actions()  
  #server.handle_request()
  server.serve_forever()
  logging.debug("Server closed")
