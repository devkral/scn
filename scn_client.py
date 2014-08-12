#! /usr/bin/env python3
#import hashlib
import sys
import os
#import threading
import time
import sqlite3
import socket
import socketserver


from OpenSSL import SSL,crypto

from scn_base import sepm,sepc,sepu
from scn_base import scn_base_client, scn_send, scn_receive, printdebug, printerror, scn_send_bytes, init_config_folder, check_certs, generate_certs
#,scn_check_return
from scn_config import scn_client_port,secret_size,client_show_incomming_commands,default_config_folder,scn_server_port


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
    tempdata=self.scn_servs.get_node(_servername)[0].split(sepu)
    if len(tempdata)==1:
      tempdata+=[scn_server_port,]
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,tempdata[2]))
    tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tempsocket = SSL.Connection(temp_context,tempsocket)
    tempsocket.settimeout(10)
    tempsocket.connect((tempdata[0],int(tempdata[1])))
    return tempsocket
  
  def connect_to_ip(self,_url):
    tempdata=_url.split(sepu)
    if len(tempdata)==1:
      tempdata+=[scn_server_port,]
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    tempsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tempsocket = SSL.Connection(temp_context,tempsocket)
    tempsocket.settimeout(10)
    tempsocket.connect((tempdata[0],int(tempdata[1])))
    return tempsocket

  def update_service(self,_servername,_name,_service,_secrethashstring):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    scn_send("update_service"+sepc+_name+sepc+_service,_socket)
    scn_send_bytes(temp[3],_socket)
    scn_send_bytes(_secrethashstring,_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response
  
  def get_service_secrethash(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    scn_send("get_service_secrethash"+sepc+_name+sepc+_service,_socket)
    scn_send_bytes(temp[3],_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

#pub
  def register_name(self,_servername,_name):
    _socket=self.connect_to(_servername)
    _secret=os.urandom(secret_size)
    scn_send("register_name"+sepc+_name+sepc,_socket)
    scn_send_bytes(_secret,_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    if _server_response[0]=="success":
      self.scn_servs.update_service(_servername,_name,"admin",_secret)
    return _server_response
  def delete_name(self,_servername,_name):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    scn_send("delete_name"+sepc+_name+sepc,_socket)
    scn_send_bytes(temp[3],_socket,True)
    _server_response=scn_receive(_socket)
    if _server_response[0]=="success":
      self.scn_servs.delete_name(_name)
    _socket.close()
    return _server_response
  def update_name_cert(self,_servername,_name,_cert):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    scn_send("update_cert"+sepc+_name+sepc,_socket)
    scn_send_bytes(temp[3],_socket)
    scn_send_bytes(_cert,_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def update_name_message(self,_servername,_name,_message):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,"admin")
    scn_send("update_message"+sepc+_name+sepc,_socket)
    scn_send_bytes(temp[3],_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def delete_service(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    scn_send("delete_service"+sepc+_name+sepc+_service+sepc,_socket)
    scn_send_bytes(temp[3],_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()  
    return _server_response
  
  def serve_service_ip(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    scn_send("serve"+sepc+_name+sepc+_service+sepc,_socket)
    scn_send_bytes(temp[3],_socket)
    scn_send(scn_client_port+sepc+"ip"+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()  
    return _server_response
  
  def unserve_service(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    scn_send("unserve"+sepc+_name+sepc+_service+sepc,_socket)
    scn_send_bytes(temp[3],_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response
    #temp=self.scn_servs.get_(_servername,_name,_servicename)

  def update_secret(self,_servername,_name,_service):
    _secret=os.urandom(secret_size)
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    scn_send("update_secret"+sepc+_name+sepc+_service+sepc,_socket)
    scn_send_bytes(temp[3],_socket)
    scn_send_bytes(_secret,_socket,True)
    _server_response=scn_receive(_socket)
    _socket.close()
    if _server_response[0]=="success":
      self.scn_servs.update_service(_servername,_name,_service,_secret)
    return _server_response
  def use_special_service_auth(self,_servername,_name,_service,*args):
    _socket=self.connect_to(_servername)
    temp=self.scn_servs.get_service(_servername,_name,_service)
    scn_send("use_special_service_auth"+sepc+_name+sepc+_service+sepc,_socket)
    scn_send_bytes(temp[3],_socket)
    is_bytes=False
    is_end=False
    for count in range(0,len(args)):
      if count==len(args)-1:
        is_end==True
      if is_bytes==True:
        scn_send_bytes(args[count],_socket,is_end)
        is_bytes=False
      elif args[count]=="bytes":
        is_bytes=True
      elif count==len(args)-1:
        scn_send(args[count]+sepm,_socket)
      else:
        scn_send(args[count]+sepc,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def get_service(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    scn_send("get_service"+sepc+_name+sepc+_service+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  
  def get_name_message(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    scn_send("get_name_message"+sepc+_name+sepc+_service+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def get_name_cert(self,_servername,_name,_service):
    _socket=self.connect_to(_servername)
    scn_send("get_name_cert"+sepc+_name+sepc+_service+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def use_special_service_unauth(self,_servername,_name,_service,*args):
    _socket=self.connect_to(_servername)
    scn_send("use_special_service_unauth"+sepc+_name+sepc+_service+sepc,_socket)
    is_bytes=False
    is_end=False
    for count in range(0,len(args)):
      if count==len(args)-1:
        is_end==True
      if is_bytes==True:
        scn_send_bytes(args[count],_socket,is_end)
        is_bytes=False
      elif args[count]=="bytes":
        is_bytes=True
      elif count==len(args)-1:
        scn_send(args[count]+sepm,_socket)
      else:
        scn_send(args[count]+sepc,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response
  def info(self,_servername):
    _socket=self.connect_to(_servername)
    scn_send("info"+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  def update_node(self,_servername,_url):
    _socket=self.connect_to_ip(_url)
    scn_send("info"+sepm,_socket)
    _server_response=scn_receive(_socket)
    _server_cert=None #_socket.getpeercert()
    if _server_response[0]=="success" and self.scn_servs.update_node(_servername,_url,_server_response[2],_server_cert)==True:
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
    scn_send(command+sepm,_socket)
    _server_response=scn_receive(_socket)
    _socket.close()
    return _server_response

  clientactions={"register":register_name,"delname":delete_name,"updcert":update_name_cert,"updmessage": update_name_message,"updservice": update_service,"delservice":delete_service,"getservicehash": get_service_secrethash,"serveip": serve_service_ip,"unserve": unserve_service,"updsecret": update_secret,"use_auth": use_special_service_auth,"use_unauth":use_special_service_unauth,"getmessage":get_name_message,"getcert":get_name_cert,"info":info,"updserver": update_node, "delserver": delete_node,"getlist": get_node_list,"getnode":get_node}

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
            serveranswer = self.clientactions[command[0]](self,*command[1].split(sepc))
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
