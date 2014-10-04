#! /usr/bin/env python3
#import hashlib
import sys
#import os
import threading
import signal
import time
import sqlite3
import socket
import socketserver

from gi.repository import Gtk,Gdk


import os

from OpenSSL import SSL,crypto

from scn_base import sepm, sepc, sepu
from scn_base import scn_base_client,scn_base_base, scn_socket, printdebug, printerror, scn_check_return,init_config_folder, check_certs, generate_certs, scnConnectException,scn_verify_cert
#,scn_check_return
from scn_config import client_show_incomming_commands, default_config_folder, scn_server_port, max_cert_size, protcount_max,scn_host


curdir=os.path.dirname(__file__)

class client_master(object):
  receiver=None
  main=None
cm=client_master()


#scn_servs: _servicename: _server,_name:secret
class scn_friends_sql(object):
  view_cur=None
  db_path=None
  def __init__(self,_db):
    self.db_path=_db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return
    try:
      con.execute('''CREATE TABLE if not exists
      scn_friends(friendname TEXT, cert BLOB, PRIMARY KEY(friendname))''')
      con.execute('''CREATE TABLE if not exists
      scn_friends_server(friendname TEXT, servername TEXT, name TEXT,
      FOREIGN KEY(friendname) REFERENCES scn_friends(friendname) ON UPDATE CASCADE ON DELETE CASCADE,
      PRIMARY KEY(friendname,servername))''')
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
    con.close()

  def get_friend(self,_friendname):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT cert
      FROM scn_friends
      WHERE  friendname=?''',(_friendname,))
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #return cert

  #if servername=None return all
  def get_server(self,_friendname,_servername=None):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      if _servername == None:
        cur.execute('''SELECT servername
        FROM scn_friends_server
        WHERE friendname=?''',(_friendname,))
      else:
        cur.execute('''SELECT servername
        FROM scn_friends_server
        WHERE friendname=? and servername=?''',(_friendname,_servername))
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #return servernamelist

  def update_friend(self,_friendname,_cert=None):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    if self.get_friend(_friendname) is None and _cert is None:
      printerror("Error: Certificate must be specified")
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      if _cert is not None:
        cur.execute('''INSERT OR REPLACE into scn_friends(friendname,cert) values(?,?);''',(_friendname,_cert))
      else:
        cur.execute('''INSERT OR REPLACE into scn_friends(friendname) values(?);''',(_friendname,))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def del_friend(self,_friendname):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    if self.get_friend(_friendname) is None:
      printdebug("Debug: Deletion of non-existent object")
      return True
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends
      WHERE friendname=?;''',(_friendname,))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True



  def update_server(self,_friendname,_servername,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_friends_server(friendname,servername,name) values(?,?,?);''',(_friendname,_servername,_name))
      
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def del_server_friend(self,_friendname,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends_server
      WHERE friendname=? AND servername=?;''',(_friendname,_servername))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  #delete server from all friends
  def del_server_all(self,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends_server
      WHERE servername=?;''',(_servername,))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True


#scn_servs: _servicename: _server,_name:secret
class scn_servs_sql(object):
  view_cur=-1
  view_list=None
  db_path=None
  def __init__(self,_db):
    self.db_path=_db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return
    try:
      con.execute('''CREATE TABLE if not exists
      scn_serves(servername TEXT, name TEXT, service TEXT,
      secret BLOB, pending INTEGER,PRIMARY KEY(servername,name,service),
      FOREIGN KEY(servername) REFERENCES scn_certs(nodename) ON UPDATE CASCADE ON DELETE CASCADE);''')
      
      con.execute('''CREATE TABLE if not exists scn_certs(nodename TEXT,
      url TEXT,cert BLOB,PRIMARY KEY(nodename)  );''')
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
    con.close()

  def update_node(self,_nodename,_url,_cert):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_certs(nodename,url,cert) values(?,?,?);''',(_nodename,_url,_cert))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_node_name(self,_nodename,_nodename_new):
    if self.get(_nodename_new) is not None:
      return False
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False

    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_certs SET nodename=? WHERE nodename=?;''',(_nodename_new,_nodename))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_service(self,_servername,_name,_service,_secret,_pendingstate=True):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_serves(
      servername,
      name,
      service,
      secret, pending)
      values (?,?,?,?,?)''',(_servername,_name,_service,_secret,_pendingstate))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def update_service_pendingstate(self,_servername,_name,_service,_pendingstate=False):
    if _pendingstate==False:
      _pendingstate=0
    else:
      _pendingstate=1
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_serves SET pending=? WHERE
      servername=? AND name=? AND service=?;
      ''',(_servername,_name,_service,_pendingstate))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def get_service(self,_servername,_name,_servicename):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT b.url,b.cert,a.secret, a.pending
      FROM scn_serves as a,scn_certs as b
      WHERE  a.servername=? AND a.servername=b.nodename
      AND a.name=? AND a.service=?''',(_servername,_name,_servicename))
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp[0] #serverurl,cert,secret,pending state
  
  def del_service(self,_servername,_name,_servicename):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_serves
      WHERE servername=?
      AND a.name=?
      AND a.service=?''',(_servername,_name,_servicename))
      con.commit()
    except Exception as u:
      printerror(u)
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
      cur.execute('''DELETE FROM scn_serves
      WHERE servername=?
      AND a.name=?''',(_servername,_name))
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
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
      cur.execute('''DELETE FROM scn_certs
      WHERE nodename=?''',(_servername,))
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
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
      cur.execute('''SELECT url,cert
      FROM scn_certs
      WHERE nodename=?''',(_nodename,))
      temp=cur.fetchone()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #serverurl,cert or None

  def get_by_url(self,_url):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT nodename FROM scn_certs WHERE url=?''',(_url,))
      temp=cur.fetchmany()
    except Exception as u:
      printerror(u)
    con.close()
    return temp 

  def get_list(self):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      cur = con.cursor()
      cur.execute('''SELECT nodename,url FROM scn_certs''')
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp # [(servername,url),...]

  def get_next(self):
    self.view_cur+=1
    return self.view_list[self.view_cur] #name,serverurl,cert,secret,pendingstate
  def rewind(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT b.nodename,b.url,a.name,a.service,a.secret,a.pending
      FROM scn_serves as a,scn_certs as b
      WHERE a.servername=b.nodename''')
      self.view_cur=-1 #+1 before retrieving
      self.view_list=cur.fetchall()
    except Exception as u:
      printdebug(u)
    con.close()






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
  def connect_to(self,_servername):
    tempdata=self.scn_servers.get_node(_servername)
    if tempdata == None:
      raise (scnConnectException("connect_to: servername doesn't exist"))
    tempconnectdata=tempdata[0].split(sepu)
    if len(tempconnectdata)==1:
      tempconnectdata+=[scn_server_port,]
    
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,tempdata[1]))
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
  
  def c_connect_to_node(self,_servername,_name,_service="main",_com_method=None):
    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    tempsocket=None
    method=_com_method
    _cert=None
    for elem in self.c_get_service(_servername,_name,_service):
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
          if scn_verify_cert(_name,_cert,elem[2])==True:
            break
    if tempsocket == None:
      return None
    return [tempsocket, method, _cert]

  

  def call_command(self,_servername,_command):
    _socket=self.connect_to(_servername)
    _socket.send(_command)
    _server_response = []
    for protcount in range(0,protcount_max):
      _server_response += [_socket.receive_one(100),]
    _socket.close()
    print(_server_response)
    return True
    

  def c_serve_service_ip(self,_servername,_name,_service):
    return self.c_serve_service(self,_servername,_name,_service,"ip",self.linkback.receiver.host[1])
  
  def c_get_server_list(self):
    return self.scn_servers.get_list()

  def c_get_server(self,_servername):
    return self.scn_servers.get_node(_servername)

  actions = {"get_cert": scn_base_base.s_get_cert,
             "pong": scn_base_base.pong,
             "info": scn_base_base.s_info}
  #             "wrap": scn_base_client.s_wrap}


  clientactions_bool = {"register": scn_base_client.c_register_name, 
                        "delname": scn_base_client.c_delete_name, 
                        "updmessage": scn_base_client.c_update_name_message, 
                        "addservice": scn_base_client.c_add_service, 
                        "updservice": scn_base_client.c_update_service, 
                        "delservice": scn_base_client.c_delete_service, 
                        "serveip": c_serve_service_ip, 
                        "unserve": scn_base_client.c_unserve_service, 
                        "updsecret": scn_base_client.c_update_secret,
                        "addserver": scn_base_client.c_add_server,
                        "updserver": scn_base_client.c_update_server, 
                        "delserver": scn_base_client.c_delete_server}
  clientactions_list = {"getservicehash": scn_base_client.c_get_service_secrethash, 
                        "getmessage": scn_base_client.c_get_name_message, 
                        "getservercert": scn_base_client.c_get_server_cert, 
                        "info": scn_base_client.c_info, 
                        "getlist": c_get_server_list, 
                        "getnode": c_get_server}

#,"use_auth": use_special_service_auth,"use_unauth":use_special_service_unauth
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

      elif command[0] in self.clientactions_bool:
        try:
          if len(command)>1:
            tempcom=command[1].split(sepc)
            serveranswer = self.clientactions_bool[command[0]](self,*tempcom)
          else:
            serveranswer = self.clientactions_bool[command[0]](self)
        except TypeError as e:
          printerror(e)
        except BrokenPipeError:
          printdebug("Socket closed unexpected") 
        except Exception as e:
          printerror(e)
        if serveranswer == True:
          print("Command finished successfull")
        else:
          print("Command finished with errors")

      elif command[0] in self.clientactions_list:
        
        try:
          if len(command) > 1:
            tempcom = command[1].split(sepc)
            serveranswer = self.clientactions_list[command[0]](self,*tempcom)
          else:
            serveranswer = self.clientactions_list[command[0]](self)
        except TypeError as e:
          printerror(e)
        except BrokenPipeError:
          printdebug("Socket closed unexpected") 
        except Exception as e:
          printerror(e)
        if serveranswer != None:
          print(*serveranswer, sep = ", ")
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
    temp_context.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM,self.linkback.main.priv_cert))
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,self.linkback.main.pub_cert))
    self.socket = SSL.Connection(temp_context,socket.socket(self.address_family, self.socket_type))
    self.host=self.socket.getsockname()
    #self.socket.set_accept_state()
    self.server_bind()
    self.server_activate()



#

normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE
icons=Gtk.IconTheme.get_default()


#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with names on server (compressed)
#a subwindow with actions

class scnDeletionDialog(Gtk.Dialog):
  serverinfo=None
  def __init__(self, _parent, _server,_name=None,_service=None):
    self.parent=_parent
    self.name=_name
    Gtk.Dialog.__init__(self, "Confirm Deletion", self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)

    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    if _name is not None and _service is not None:
      label=Gtk.Label("Shall service \""+_service+"\" of "+_server+"/"+_name+" be deleted?")
    elif _name is not None and _service is None:
      label=Gtk.Label("Shall name \""+_name+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()


class scnServerEditDialog(Gtk.Dialog):
  servername=None
  urlname=None
  def __init__(self, _parent, _title, _servername,_url=""):
    self.parent=_parent
    self.servername=Gtk.Entry()
    self.servername.set_hexpand(True)
    self.servername.set_text(_servername)
    self.url=Gtk.Entry()
    self.url.set_hexpand(True)
    self.url.set_text(_url)
    
    Gtk.Dialog.__init__(self, _title, self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    box = self.get_content_area()
    cont=Gtk.Grid()
    box.add(cont)

    tsname=Gtk.Label("Servername: ")
    tsname.set_halign(Gtk.Align.END)
    cont.attach(tsname,0,0,1,1)
    cont.attach(self.servername,1,0,1,1)
    turl=Gtk.Label("Url: ")
    turl.set_halign(Gtk.Align.END)
    cont.attach(turl,0,1,1,1)
    cont.attach(self.url,1,1,1,1)

    self.show_all()

class scnNameAddDialog(Gtk.Dialog):
  name=None
  def __init__(self, _parent, _title,_servername,_parentname=None):
    self.parent=_parent
    self.name=Gtk.Entry()
    self.name.set_hexpand(True)
#    self.name.set_text(_name)
    
    Gtk.Dialog.__init__(self, _title, self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    box = self.get_content_area()
    cont=Gtk.Grid()
    box.add(cont)
    lname=Gtk.Label()
    if _parentname==None:
      lname.set_text("On "+_servername+" add:")
    else:
      lname.set_text("On "+_servername+": add to "+_parentname+":")
    lname.set_halign(Gtk.Align.START)
    cont.attach(lname,0,0,2,1)
    
    tname=Gtk.Label("Name: ")
    tname.set_halign(Gtk.Align.END)
    cont.attach(tname,0,1,1,1)
    cont.attach(self.name,1,1,1,1)

    self.show_all()




#debug code


def print_tree_store(store):
    rootiter = store.get_iter_first()
    print_rows(store, rootiter, "")

def print_rows(store, treeiter, indent):
    while treeiter != None:
        print (indent + str(store[treeiter][:]))
        if store.iter_has_child(treeiter):
            childiter = store.iter_children(treeiter)
            print_rows(store, childiter, indent + "\t")
        treeiter = store.iter_next(treeiter)




class scnPageNavigation(Gtk.Grid):
  parent=None
  linkback=None

  cur_server=None #use only after set by scnupdate
  cur_name=None #use only after set by scnupdate
  cur_service=None #use only after set by scnupdate
  
  def __init__(self,_parent):
    Gtk.Grid.__init__(self)
    self.parent=_parent
    self.linkback=self.parent.linkback

    self.set_row_spacing(2)
    self.set_margin_left(5)
    self.set_margin_right(5)
    self.set_margin_top(5)
    self.set_margin_bottom(2)

    self.navbar=Gtk.Entry()
    self.navbar.connect("activate",self.navbarupdate)
    self.navcontent=Gtk.ListStore(str)
    self.navbox=Gtk.TreeView(self.navcontent)
    renderer = Gtk.CellRendererText()
    self.listelems = Gtk.TreeViewColumn("Title", renderer, text=0)
    self.navbox.append_column(self.listelems)
    self.navbox.get_selection().set_mode(Gtk.SelectionMode.BROWSE)
    self.navbox.set_vexpand(True)
    self.navcontextmain=Gtk.Frame()
    #self.navcontextmain.set_margin_right(5)
    self.navcontextmain.set_hexpand(True)
    self.navcontextmain.set_shadow_type(Gtk.ShadowType.NONE)

    navcontainer=Gtk.Grid()
    navcontainer.set_column_spacing(2)

    #navcontainer.set_margin_top(2)
    #navcontainer.set_margin_left(5)
    #navcontainer.set_margin_right(5)
    labelnavbar=Gtk.Label("Navigation: ")
    navbarconfirm=Gtk.Button("OK")
    navbarconfirm.connect("clicked",self.navbarupdate)
    navcontainer.attach(labelnavbar,0,0,1,1)
    self.navbar.set_hexpand (True)
    navcontainer.attach(self.navbar,1,0,1,1)
    navcontainer.attach(navbarconfirm,2,0,1,1)

    self.attach(navcontainer,0,0,2,1)
    self.attach(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL),0,1,2,1)

    frame_nav=Gtk.Frame()
    frame_nav.add(self.navbox)
    frame_nav.set_margin_left(5)
    frame_nav.set_margin_right(5)

    #self.attach(self.navcontextsmall,0,2,1,1)
    self.attach(frame_nav,0,2,1,1)

    
    self.navcontextmain.set_label_align(0.1,0.8)
    self.attach(self.navcontextmain,1,2,1,1)
    self.update()


  def update(self,_server=None,_name=None,_service=None):
    self.cur_server=_server
    self.cur_name=_name
    self.cur_service=_service
    if _service is not None:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      
      self.navbar.set_text(self.cur_server+"/"+self.cur_name+"/"+self.cur_service)
      self.buildservicegui()

    elif _name is not None:
      self.navbar.set_text(self.cur_server+"/"+self.cur_name+"/")
      self.buildnamegui()

    elif _server is not None:
      self.navbar.set_text(self.cur_server+"/")
      self.buildservergui()
      
    else:
      self.navbar.set_text("")
      self.buildNonegui()
  #update by navbar
  def navbarupdate(self, *args):
    splitnavbar=self.navbar.get_text().strip("/").rstrip("/").split("/")
    self.update(*splitnavbar[:3])

  def updateserverlist(self):
    temp2=self.linkback.main.scn_servers.get_list()
    if temp2 is None:
      return False
    self.listelems.set_title("Server")
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.5, 0.5, 1, 1))
    self.navbox.show()
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem[0],))

  def updatenamelist(self):
    temp_names=self.linkback.main.c_list_names(self.cur_server)
    if temp_names is None:
      return False
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0.7, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Name")
    self.navcontent.clear()
    for elem in temp_names:
      self.navcontent.append((elem,))
    return True

  def updateservicelist(self):
    temp2=self.linkback.main.c_list_services(self.cur_server,self.cur_name)
    if temp2 is None:
      return False
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Service")
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem,))

  def buildNonegui(self):
    if self.updateserverlist()==False:
      self.state_widget.set_text("Error loading servers")
    #label counts as child, so ignore it
    if len(self.navcontextmain.get_children())==1:
      #print(self.navcontextmain.get_children())
      self.navcontextmain.get_children()[0].destroy()
      #self.navcontextmain.set_label("Context")
    #build grid for contextarea
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)
    contextcont.set_row_spacing(2)
    #contextcont.set_border_width(3)
    contextcont.attach(Gtk.Label("Actions:"),0,0,1,1)
    addServerButton1=Gtk.Button("Add Server")
    addServerButton1.connect("clicked", self.add_server)
    contextcont.attach(addServerButton1,0,1,1,1)
    deleteServerButton1=Gtk.Button("Delete Server")
    deleteServerButton1.connect("clicked", self.delete_server)
    contextcont.attach(deleteServerButton1,0,2,1,1)
    
    editServerButton1=Gtk.Button("Edit Server")
    editServerButton1.connect("clicked", self.edit_server2)
    contextcont.attach(editServerButton1,0,3,1,1)

    goServerButton1=Gtk.Button("Use Server")
    goServerButton1.connect("clicked", self.select_server)
    contextcont.attach(goServerButton1,0,4,1,1)
    self.navcontextmain.show_all()


  def buildservergui(self):
    if self.updatenamelist()==False:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return

    if len(self.navcontextmain.get_children())==1:
      #print(self.navcontextmain.get_children())
      self.navcontextmain.get_children()[0].destroy()
      #print(self.navcontextmain.get_children())
    #build grid for contextarea
    contextcont=Gtk.Grid()
    contextcont.set_column_spacing(2)
    self.navcontextmain.add(contextcont)

    
    ### server actions ###

    servercont_f=Gtk.Frame()
    servercont_f.set_label("Server actions")
    servercont=Gtk.Grid()
    servercont.set_row_spacing(2)
    servercont.set_border_width(2)
    servercont_f.add(servercont)
    contextcont.attach(servercont_f,0,0,1,1)

    deleteServerButton3=Gtk.Button("Delete server")
    deleteServerButton3.connect("clicked", self.delete_server2)
    servercont.attach(deleteServerButton3,0,0,1,1)
    
    editServerButton1=Gtk.Button("Edit Server")
    editServerButton1.connect("clicked", self.edit_server2)
    servercont.attach(editServerButton1,0,1,1,1)

    
    goNoneButton2=Gtk.Button("Go back")
    goNoneButton2.connect("clicked", self.goback_none)
    servercont.attach(goNoneButton2,0,2,1,1)

    goNameButton1=Gtk.Button("Select Name")
    goNameButton1.connect("clicked", self.select_name)
    servercont.attach(goNameButton1,0,3,1,1)
    
    ### name actions ###

    namecont_f=Gtk.Frame()
    namecont_f.set_label("Name actions")
    namecont=Gtk.Grid()
    namecont.set_row_spacing(2)
    namecont.set_border_width(2)
    namecont_f.add(namecont)
    contextcont.attach(namecont_f,1,0,1,1)


    addNameButton1=Gtk.Button("Register Name")
    addNameButton1.connect("clicked", self.register_name)
    namecont.attach(addNameButton1,0,0,1,1)
    

    deleteNameButton3=Gtk.Button("Delete Name")
    deleteNameButton3.connect("clicked", self.delete_name2)
    namecont.attach(deleteNameButton3,0,1,1,1)


    ### space for message
    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Server Message")
    tempmessage=self.linkback.main.c_get_server_message(self.cur_server)
    tempshowlabel=Gtk.Label()
    tempshowlabel.set_halign(Gtk.Align.START)
    tempshowlabel.set_valign(Gtk.Align.START)
    tempshowlabel.set_hexpand(True)
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,2,0,1,1)

#    self.servercont_f.show_all()
#    self.namecont_f.show_all()
    self.navcontextmain.show_all()

  def buildnamegui(self):
    
    if self.updateservicelist()==False:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(1, 0, 0, 1))
      self.buildservergui()
      return

    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
    #build grid for contextarea
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)

    namecont_f=Gtk.Frame()
    namecont_f.set_label("Name actions")
    namecont=Gtk.Grid()
    namecont.set_row_spacing(2)
    namecont.set_border_width(2)
    namecont_f.add(namecont)
    contextcont.attach(namecont_f,0,0,1,1)

    goServerButton2=Gtk.Button("Go back")
    goServerButton2.connect("clicked", self.goback_server)
    namecont.attach(goServerButton2,0,0,1,1)

    goServiceButton1=Gtk.Button("Select Service")
    goServiceButton1.connect("clicked", self.select_service)
    namecont.attach(goServiceButton1,0,1,1,1)



    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Message")
    tempmessage=self.linkback.main.c_get_name_message(self.cur_server,self.cur_name)
    tempshowlabel=Gtk.Label()
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,0,1,1,1)


    self.navcontextmain.show_all()

  def buildservicegui(self):
    if self.cur_server is None or self.cur_name is None or self.cur_service is None:
      self.buildnamegui()
      return
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 0.7, 0.7, 1))
    self.listelems.set_title("")
    self.navcontent.clear()
    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()

    self.navcontextmain.show_all()

  def genservicecontext(self,_service):
    pass


  ### select section  ###
  def goback_none(self,*args):
    self.update()

  def select_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(temp[0][temp[1]][0])

  def goback_server(self,*args):
    self.update(self.cur_server)

  def select_name(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,temp[0][temp[1]][0])

  def goback_name(self,*args):
    self.update(self.cur_server,self.cur_name) 
  
  def select_service(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,self.cur_name,temp[0][temp[1]][0])
    
  ### server section ###

  def delete_server_intern(self,_delete_server):
    dialog = scnDeletionDialog(self.parent,_delete_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_server(_delete_server)==True:
          self.updateserverlist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
      else:
        self.parent.state_widget.set_text("Aborted")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()

  #get server by navbox
  def delete_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.delete_server_intern(temp[0][temp[1]][0])

  #get server by current selection
  def delete_server2(self,*args):
    if self.cur_server is None:
      return
    self.delete_server_intern(self.cur_server)
    self.update()


  def add_server(self,*args):
    dialog = scnServerEditDialog(self.parent,"Add new server","","")
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_add_server(dialog.servername.get_text(),dialog.url.get_text())==True:
          self.updateserverlist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
      else:
        self.parent.state_widget.set_text("Error")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    
  def edit_server2(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.edit_server_intern(temp[0][temp[1]][0])

  def edit_server(self,*args):
    self.edit_server_intern(self.cur_server)

  def edit_server_intern(self,_server):
    dialog = scnServerEditDialog(self.parent,"Edit server",_server,"")
    try:
      if dialog.run()==True:
        if dialog.servername!=self.cur_server:
          self.linkback.main.scn_servers.update_node_name(self.cur_server,dialog.servername)
          
        if self.linkback.main.c_update_server(dialog.servername,dialog.url)==True:
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
      else:
        self.parent.state_widget.set_text("")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()

  def register_name(self,*args):
    dialog = scnNameAddDialog(self.parent,"Register",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_register_name(self.cur_server,dialog.name.get_text())==True:
          self.updateserverlist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
      else:
        self.parent.state_widget.set_text("Error")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()


  def delete_name_intern(self,_delete_name):
    dialog = scnDeletionDialog(self.parent,self.cur_server,_delete_name)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_name(self.cur_server,_delete_name)==True:
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
      else:
        self.parent.state_widget.set_text("Aborted")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()

  def delete_name(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.delete_name_intern(temp[0][temp[1]][0])
    self.updatenamelist()


  def delete_name2(self, *args):
    self.delete_name_intern(self.cur_name)
    self.updatenamelist()
    self.update(self.cur_server)
  ### name/service section ###




"""
class scnPageServers(Gtk.Frame):
  parent=None
  def __init__(self,_parent):
    Gtk.Frame.__init__(self)
    self.parent=_parent
    cont=Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    self.serverlist=Gtk.ListBox()#orientation=Gtk.Orientation.VERTICAL)
    cont.pack_start(self.serverlist,True,True,0)
    controls=Gtk.Grid()
    cont.pack_start(controls,True,True,0)
    add_server_button=Gtk.Button("Add Server")
    add_server_button.connect("clicked", self.add_server)
    controls.attach(add_server_button,0,0,1,1)
    self.add(cont)
    self.update()
    self.show_all()
    
  def update(self):
    for elem in self.parent.linkback.main.scn_servers.get_list():
      self.serverlist.add(scnServerNode(elem[0],self.parent))

  def add_server(self,button):
    pass"""

class scnPageFriends(Gtk.Grid):
  parent=None
  linkback=None
  def __init__(self,_parent):
    Gtk.Grid.__init__(self)
    self.parent=_parent
    self.linkback=self.parent.linkback
    self.attach(Gtk.Label("Not implemented yet"),0,0,1,1)


class scnGUI(Gtk.Window):
  confirm_button_id=None
  reset_button_id=None
  state_widget=None
  note_main=None
  linkback=None
  def __init__(self,_linkback):
    Gtk.Window.__init__(self, title="Secure Communication Nodes")
    self.linkback=_linkback
    self.resize(600,400)
    self.set_icon_from_file("icon.png")

    main_wid=Gtk.Grid()

    self.note_switch=Gtk.Notebook()
    self.note_switch.set_margin_left(5)
    self.note_switch.set_margin_right(5)
    self.note_switch.set_hexpand(True)
    self.note_switch.set_vexpand(True)
    main_wid.attach(self.note_switch,0,0,1,1)
    self.state_widget=Gtk.Label("")
    self.state_widget.set_hexpand(True)
    self.state_widget.set_margin_top(5)
    main_wid.attach(self.state_widget,0,1,1,1)

    #add=Gtk.Button(label="add")
    #add.connect("clicked", self.click_add)
    
    #.set_margin_left(5)
    #self.confirm_button=Gtk.Button("Apply")
    #self.reset_button=Gtk.Button("Reset")


    #self.main_grid.set_column_spacing(10)
    #self.main_grid.set_row_spacing(20)
    self.note_switch.append_page(scnPageNavigation(self),Gtk.Label("Server Navigation"))
#    self.note_switch.append_page(scnPageServers(self),Gtk.Label("Servermanagement"))
    self.note_switch.append_page(scnPageFriends(self),Gtk.Label("Friends"))
    
    self.note_switch.append_page(Gtk.Label("Not implemented yet"),Gtk.Label("Settings"))
    self.add(main_wid)


win=None

def signal_handler(_signal, frame):
  #win.close()
  win.destroy()
  Gtk.main_quit()
  #app.close()
  sys.exit(0)

if __name__ == "__main__":
  cm.main=scn_client(cm,default_config_folder)

  handler=scn_server_client
  handler.linkback=cm
  cm.receiver = scn_sock_client((scn_host, 0),handler, cm)
  #port 0 selects random port
  signal.signal(signal.SIGINT, signal_handler)
  client_thread = threading.Thread(target=cm.receiver.serve_forever)
  client_thread.daemon = True
  client_thread.start()

  win = scnGUI(cm)
  
  win.connect("delete-event", Gtk.main_quit)
  #win.connect("destroy", Gtk.main_quit) 

  win.show_all()
  Gtk.main()
  
  sys.exit(0)

"""  app.run(host='localhost', port=8080, debug=True)

  client_interact_thread = threading.Thread(target=run(host='localhost', port=8080))
  client_interact_thread = True
  client_interact_thread.start()
  
  t.debug()"""

