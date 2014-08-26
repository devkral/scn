#! /usr/bin/env python3
#import hashlib
import sys
#import os
#import threading
import time
import sqlite3
import socket
import socketserver


from OpenSSL import SSL,crypto

from scn_base import sepm, sepc, sepu
from scn_base import scn_base_client, scn_socket, printdebug, printerror, scn_check_return,init_config_folder, check_certs, generate_certs
#,scn_check_return
from scn_config import scn_client_port, client_show_incomming_commands, default_config_folder, scn_server_port, max_cert_size, protcount_max


#scn_servs: _servicename: _server,version,_name:secret
class scn_servs_sql(object):
  view_cur=None
  db_path=None
  def __init__(self,_db):
    self.db_path=_db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return
    try:
      con.execute('''CREATE TABLE if not exists scn_serves(servername TEXT, name TEXT,service TEXT, secret BLOB,PRIMARY KEY(servername,name,service),FOREIGN KEY(servername) REFERENCES scn_certs(nodename) ON UPDATE CASCADE  );''')
      
      con.execute('''CREATE TABLE if not exists scn_certs(nodename TEXT, url TEXT UNIQUE, version TEXT,cert BLOB,PRIMARY KEY(nodename)  );''')
      con.commit()
    except Exception as u:
      printdebug(u)
      con.rollback()
    con.close()

  def update_node(self,_nodename,_url,_version,_cert):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_certs(nodename,url,version,cert) values(?,?,?,?);''',(_nodename,_url,_version,_cert))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_service(self,_servername,_name,_service,_secret):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_serves(nodename,service,secret) values (?,?,?)''',(_servername,_service,_secret))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True
  def get_service(self,_servername,_name,_servicename):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT b.url,b.version,b.cert,a.secret FROM scn_serves as a,scn_certs as b WHERE  a.servername=? AND a.servername=b.nodename AND a.name=? AND a.service=?''',(_servername,_name,_servicename))
      temp=cur.fetchall()
    except Exception as u:
      printdebug(u)
    con.close()
    return temp #serverurl,version,cert,secret
  
  def del_service(self,_servername,_name,_servicename):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_serves WHERE  servername=? AND a.name=? AND a.service=?''',(_servername,_name,_servicename))
    except Exception as u:
      printdebug(u)
      return False
    con.close()
    return True

  
  def del_name(self,_servername,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_serves WHERE  servername=? AND a.name=?''',(_servername,_name))
    except Exception as u:
      printdebug(u)
      return False
    con.close()
    return True

  
  def del_node(self,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_certs WHERE nodename=?''',(_servername,))
    except Exception as u:
      con.rollback()
      printdebug(u)
      return False
    con.close()
    return True

  def get_node(self,_nodename):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT url,version,cert FROM scn_certs WHERE nodename=?''',(_nodename,))
      temp=cur.fetchone()
    except Exception as u:
      printdebug(u)
    con.close()
    return temp #serverurl,version,cert

  def get_list(self):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      cur = con.cursor()
      cur.execute('''SELECT nodename FROM scn_certs''')
      temp=cur.fetchall()
    except Exception as u:
      printdebug(u)
    con.close()
    return temp #serverurl,version,cert

  def get_next(self):
    return self.view_cur.fetchone() #serverurl,version,secret,cert
  def rewind(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT b.url,b.version,b.cert,a.name,a.secret FROM scn_serves as a,scn_certs as b WHERE a.servername=b.nodename''')
      self.view_cur=cur
    except Exception as u:
      printdebug(u)
    con.close()



class scn_client(scn_base_client):
  _incommingbuffer=[]
  is_active=True
  config_path=""

  def __init__(self,_config_path):
    self.version="1"
    self.config_path=_config_path
    init_config_folder(self.config_path)
    if check_certs(self.config_path+"scn_client_cert")==False:
      printdebug("private key not found. Generate new...")
      generate_certs(self.config_path+"scn_client_cert")
    with open(self.config_path+"scn_client_cert"+".priv", 'r') as readinprivkey:
      self.priv_cert=readinprivkey.read()
    with open(self.config_path+"scn_client_cert"+".pub", 'r') as readinpubkey:
      self.pub_cert=readinpubkey.read()

    self.scn_servs=scn_servs_sql(self.config_path+"scn_client_db")
#priv
  def connect_to(self,_servername):
    tempdata=self.scn_servs.get_node(_servername)
    tempconnectdata=tempdata[0].split(sepu)
    if len(tempconnectdata)==1:
      tempconnectdata+=[scn_server_port,]
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    print(tempdata[2])
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,tempdata[2]))
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
        if count<2:
          printdebug(e)
        else:
          raise(e)
    return tempsocket
  
  def connect_to_ip(self,_url):
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
        if count<2:
          printdebug(e)
        else:
          raise(e)
    return tempsocket

  def update_node(self,_url,_servername=None):
    _socket=scn_socket(self.connect_to_ip(_url))
    _socket.send("info"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return
    if _servername == None:
      _servername=_socket.receive_one()
    else:
      _socket.receive_one()
    _version=_socket.receive_one()
    _socket.receive_one()#_serversecretsize=
    if _socket.is_end() == False:
      printerror("is not end before executing second command")
      _socket.close()
      return
    _socket.send("get_server_cert"+sepm)
    if scn_check_return(_socket) == False:
      _socket.close()
      return
    _cert=_socket.receive_bytes(0,max_cert_size)
  
    if self.scn_servs.update_node(_servername,_url,_version,_cert)==True:
      return ["success",]
    else:
      return ["error","node update failed"]
    
  def delete_node(self,_servername):
    if self.scn_servs.del_node(_servername)==True:
      return ["success",]
    else:
      return ["error","node update failed"]
  
  def get_node_list(self):
    return ["success",]+self.scn_servs.get_list()

  def get_node(self,_nodename):
    temp=self.scn_servs.get_node(_nodename)
    return ["success",temp[0],temp[1],temp[2]]


  def call_command(self,_servername,command):
    _socket=self.connect_to(_servername)
    _socket.send(command)
    _server_response = []
    for protcount in range(0,protcount_max):
      _server_response += [_socket.receive_one(100),]
    _socket.close()
    return _server_response
    
  
  def serve_service_ip(self,_servername,_name,_service):
    _socket=scn_socket(self.connect_to(_servername))
    temp=self.scn_servs.get_service(_servername,_name,_service)
    _socket.send("serve"+sepc+_name+sepc+_service+sepc)
    _socket.send_bytes(temp[3])
    _socket.send(scn_client_port+sepc+"ip"+sepm)
    _server_response=scn_check_return(_socket)
    _socket.close()
    return _server_response

  clientactions={"register": scn_base_client.register_name, \
                 "delname": scn_base_client.delete_name, \
                 "updcert": scn_base_client.update_name_cert, \
                 "updmessage": scn_base_client.update_name_message, \
                 "updservice": scn_base_client.update_service, \
                 "delservice": scn_base_client.delete_service, \
                 "getservicehash": scn_base_client.get_service_secrethash, \
                 "serveip": serve_service_ip, \
                 "unserve": scn_base_client.unserve_service, \
                 "updsecret": scn_base_client.update_secret, \
                 "getmessage": scn_base_client.get_name_message, \
                 "getcert": scn_base_client.get_name_cert, \
                 "info": scn_base_client.info, \
                 "updserver": update_node, \
                 "delserver": delete_node, \
                 "getlist": get_node_list, \
                 "getnode":get_node}
#,"use_auth": use_special_service_auth,"use_unauth":use_special_service_unauth
  def debug(self):
    while self.is_active==True:
      serveranswer=None
      print("Enter:")
      try:
        command=sys.stdin.readline().strip("\n").replace(":",sepu).replace(",",sepc).split(sepc,1)
      except KeyboardInterrupt:
        self.is_active=False
        break
      if command[0]=="call":
        try:
          self.call_command(self,command[1].split(sepc,1))
        except Exception as e:
          printdebug(e)

      elif command[0] not in self.clientactions:
        printerror("No such function")
      else:
        try:
          if len(command)>1:
            tempcom=command[1].split(sepc)
            serveranswer = self.clientactions[command[0]](self,*tempcom)
          else:
            serveranswer = self.clientactions[command[0]](self)
        except TypeError as e:
          printdebug(command)
          printdebug(e)
          printerror("Invalid number of parameters")
        except Exception as e:
          printerror(e)
      if serveranswer != None:
        print(serveranswer[0])
        if len(serveranswer)>1:
          print(*serveranswer[1:],sep = ", ")
      if client_show_incomming_commands == True and len(self._incommingbuffer) > 0:
        print(self._incommingbuffer.pop(0))
      time.sleep(1)
  

class scn_client_handler(socketserver.BaseRequestHandler):
  linkback=None
  def handle(self):
    pass

def signal_handler(signal, frame):
        sys.exit(0)
if __name__ == "__main__":
    t=scn_client(default_config_folder)
#    t.register_client()
    #thr2=threading.Thread(target=t.handle)
    #thr2.daemon=True
    #thr2.start()
    t.debug()
