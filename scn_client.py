#! /usr/bin/env python3
#import hashlib
import sys
#import os
import time
import sqlite3
import socket
import socketserver

import threading
import signal


import os

from OpenSSL import SSL,crypto

from scn_base import sepm, sepc, sepu
from scn_base import scn_base_client,scn_base_base, scn_socket, printdebug, printerror, scn_check_return,init_config_folder, check_certs, generate_certs, scnConnectException,scn_verify_ncert
#,scn_check_return
from scn_config import client_show_incomming_commands, default_config_folder, scn_server_port, max_cert_size, protcount_max,scn_host

from backend.sqlite.client import scn_friends_sql,scn_servs_sql

curdir=os.path.dirname(__file__)

class client_master(object):
  receiver=None
  main=None
cm=client_master()







class scn_client(scn_base_client):
  _incommingbuffer=[]
  is_active=True
  config_path=""
  linkback=None

  def __init__(self,_linkback,_config_path):
    self.version="1"
    self.linkback=_linkback
    self.config_path=_config_path
    init_config_folder(self.config_path)
    if check_certs(self.config_path+"scn_client_cert")==False:
      printdebug("private key not found. Generate new...")
      generate_certs(self.config_path+"scn_client_cert")
    with open(self.config_path+"scn_client_cert"+".priv", 'rb') as readinprivkey:
      self.priv_cert=readinprivkey.read()
    with open(self.config_path+"scn_client_cert"+".pub", 'rb') as readinpubkey:
      self.pub_cert=readinpubkey.read()

    self.scn_servers=scn_servs_sql(self.config_path+"scn_client_server_db")
    self.scn_friends=scn_friends_sql(self.config_path+"scn_client_friend_db")

#connect methods
  def connect_to(self,_server):
    tempdata=self.scn_servers.get_server(_server)
    if tempdata == None:
      raise (scnConnectException("connect_to: servername doesn't exist"))
    return self.connect_to_url(*tempdata[:2])
      
  def connect_to_url(self,_url,_cert):
    #split ip address and port 
    tempconnectdata=_url.split(sepu)
    if len(tempconnectdata)==1:
      tempconnectdata+=[scn_server_port,]
    
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,_cert))
    for count in range(0,3):
      tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      #don't use settimeout, pyopenssl error
      tempsocket = SSL.Connection(temp_context,tempsocket)
      try:
        #connect with ssl handshake
        tempsocket.connect((tempconnectdata[0],int(tempconnectdata[1])))
        tempsocket.do_handshake()
        break
      except Exception as e:
        raise(e)
      #  if count<2:
      #    printdebug(e)
      #  else:
      #    raise(e)
    tempsocket.setblocking(True)
    return tempsocket
  
  def connect_to_ip(self,_url):
    if bool(_url)==False:
      return None
    tempconnectdata=_url.split(sepu)
    if len(tempconnectdata)==1:
      tempconnectdata+=[scn_server_port,]
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")

    for count in range(0,3):
      tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      #don't use settimeout, pyopenssl error
      tempsocket = SSL.Connection(temp_context,tempsocket)
      try:
        #connect with ssl handshake
        tempsocket.connect((tempconnectdata[0],int(tempconnectdata[1])))
        tempsocket.do_handshake()
        break
      except Exception as e:
        raise(e)
    tempsocket.setblocking(True)
    return tempsocket
  
  def c_connect_to_node(self,_server,_domain,_channel="main",_com_method=None):
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    tempsocket=None
    method=_com_method
    _cert=None
    for elem in self.c_get_channel(_server,_domain,_channel):
      if _com_method is None:
        method=elem[0]
      if method=="ip" or method=="wrap":
        tempconnectdata=elem[1].split(sepu)
        if len(tempconnectdata)==1:
          tempconnectdata+=[scn_server_port,]
        for count in range(0,3):
          tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          #don't use settimeout, pyopenssl error
          tempsocket = SSL.Connection(temp_context,tempsocket)
          try:
            #connect with ssl handshake
            tempsocket.connect((tempconnectdata[0],int(tempconnectdata[1])))
            tempsocket.do_handshake()
            tempsocket.setblocking(True)
            break
          except Exception as e:
            raise(e)
      if tempsocket is not None:
        tempcomsock2=scn_socket(tempsocket)
        tempcomsock2.send("get_cert")
        if scn_check_return(tempcomsock2)==True:
          _cert=tempcomsock2.receive_bytes(0,max_cert_size)
          if scn_verify_ncert(_domain,_cert,elem[2])==True:
            break
    if tempsocket == None:
      return None
    return [tempsocket, method, _cert]

  def update_serves(self):
    for serveob in self.scn_servers.list_serves(True):
      #temp=self.scn_servers.get_channel(*serveid[:3])
      threading.Thread(target=self.update_single_serve,args=serveob)

  # _serveob= server,name,channel,type,pending state,active
  def update_single_serve(self,_serveob):
    if bool(_serveob[5])==False:
      return
    while True:
      addr=""
      if _serveob[3]=="ip":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("www.google.com",80))
        addr=s.getsockname()[0]
        s.close()
      self.c_serve_channel(_serveob[0],_serveob[1],_serveob[2],_serveob[3],addr)
    
    if bool(_serveob[4])==True:
      self.scn_servers.update_pendingstate(_serveob[0],_serveob[1],_serveob[2],False)
      _serveob[4]=False
    #c_serve_channel(_inob)
    
      

  def call_command(self,_servername,_command):
    _socket=self.connect_to(_servername)
    _socket.send(_command)
    _server_response = []
    for protcount in range(0,protcount_max):
      _server_response += [_socket.receive_one(100),]
    _socket.close()
    print(_server_response)
    return True

  def c_serve_channel_ip(self,_servername,_domain,_channel):
    return self.c_serve_channel(self,_servername,_domain,_channel,"ip",self.linkback.receiver.host[1])
  
  def c_get_server_list(self):
    return self.scn_servers.list_servers()

  def c_get_server(self,_servername):
    return self.scn_servers.get_server(_servername)

  actions = {"get_cert": scn_base_base.s_get_cert,
             "pong": scn_base_base.pong,
             "info": scn_base_base.s_info}
  #             "wrap": scn_base_client.s_wrap}


  clientactions = {"register": scn_base_client.c_register_domain, 
                   "deldomain": scn_base_client.c_delete_domain, 
                   "updmessage": scn_base_client.c_update_message,
                   "chkdomain": scn_base_client.c_check_domain,
                   "addchannel": scn_base_client.c_add_channel, 
                   "updchannel": scn_base_client.c_update_channel, 
                   "delchannel": scn_base_client.c_delete_channel, 
                   "serveip": c_serve_channel_ip, 
                   "unserve": scn_base_client.c_unserve_channel, 
                   "updsecret": scn_base_client.c_update_secret,
                   "addserver": scn_base_client.c_add_server,
                   "updserver": scn_base_client.c_update_server, 
                   "delserver": scn_base_client.c_delete_server,
                   "getchannelhash": scn_base_client.c_get_channel_secrethash, 
                   "getmessage": scn_base_client.c_get_domain_message, 
                   "getservercert": scn_base_client.c_get_server_cert, 
                   "info": scn_base_client.c_info, 
                   "getlist": c_get_server_list, 
                   "getnode": c_get_server}

#,"use_auth": use_special_channel_auth,"use_unauth":use_special_channel_unauth
  def debug(self):
    while self.is_active == True:
      serveranswer = None
      print("Enter:")
      try:
        command = sys.stdin.readline().strip("\n").replace(":",sepu).replace(",",sepc).split(sepc,1)
      except KeyboardInterrupt:
        self.is_active = False
        break
      if command[0] == "call":
        try:
          self.call_command(self,command[1].split(sepc,1))
        except Exception as e:
          printerror(e)

      elif command[0] in self.clientactions:
        try:
          if len(command)>1:
            tempcom=command[1].split(sepc)
            serveranswer = self.clientactions[command[0]](self,*tempcom)
          else:
            serveranswer = self.clientactions[command[0]](self)
        except TypeError as e:
          printerror(e)
        except BrokenPipeError:
          printdebug("Socket closed unexpected") 
        except Exception as e:
          printerror(e)
        if isinstance(serveranswer,bool)==True:
          print(serveranswer)
        elif isinstance(serveranswer,list)==True or isinstance(serveranswer,tuple)==True:
          print(*serveranswer, sep = ", ")
        else:
          print("Not recognized")
      else:
        print(command)
        printerror("No such function client")
        
      if client_show_incomming_commands == True and len(self._incommingbuffer) > 0:
        print(self._incommingbuffer.pop(0))
      time.sleep(1)
  

#for requests to client
class scn_server_client(socketserver.BaseRequestHandler):
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
          self.linkback.main.actions[temp](self.linkback,sc)
        else:
          sc.send("error"+sepc+temp+sepc+"no such function"+sepm)
      except BrokenPipeError:
        printdebug("Socket closed") 
        break
      except Exception as e:
        printdebug(e)
        break

#use here socketserver.ThreadingMixIn because no changes will be committed
class scn_sock_client(socketserver.ThreadingMixIn, socketserver.TCPServer):
  linkback=None
  host=None
  def __init__(self, client_address, HandlerClass,_linkback):
    socketserver.BaseServer.__init__(self, client_address, HandlerClass)
    self.linkback=_linkback

    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    temp_context.use_privatekey(
      crypto.load_privatekey(crypto.FILETYPE_PEM,
                             self.linkback.main.priv_cert))
    temp_context.use_certificate(crypto.load_certificate(
      crypto.FILETYPE_PEM,self.linkback.main.pub_cert))
    self.socket = SSL.Connection(temp_context,
                                 socket.socket(self.address_family, self.socket_type))
    self.host=self.socket.getsockname()
    #self.socket.set_accept_state()
    self.server_bind()
    self.server_activate()



#


#  app.run(host='localhost', port=8080, debug=True)

#  client_interact_thread = threading.Thread(target=run(host='localhost', port=8080))
#  client_interact_thread = True
#  client_interact_thread.start()
#  
#  t.debug()"""


def signal_handler(_signal, frame):
  sys.exit(0)

if __name__ == "__main__":
  cm.main=scn_client(cm,default_config_folder)

  handler=scn_server_client
  handler.linkback=cm
  cm.receiver = scn_sock_client((scn_host, 0),handler, cm)
  # port 0 selects random port
  signal.signal(signal.SIGINT, signal_handler)
  client_thread = threading.Thread(target=cm.receiver.serve_forever)
  client_thread.daemon = True
  client_thread.start()
  cm.main.debug()
  
  sys.exit(0)
