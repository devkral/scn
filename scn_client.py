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
    if self.get_friend(_friendname)==None and _cert==None:
      printerror("Error: Certificate must be specified")
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      if _cert!=None:
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
    if self.get_friend(_friendname)==None:
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
      if _com_method==None:
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
      if tempsocket!=None:
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
        if temp==None:
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




#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with names on server (compressed)
#a subwindow with actions

class scnDeletionDialog(Gtk.Dialog):
  serverinfo=None
  def __init__(self, _parent, _server,_name=None,_service=None):
    self.parent=_parent
    self.name=_name
    Gtk.Dialog.__init__(self, "Confirm Deletion", self.parent, 0,
-                        (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
-                         Gtk.STOCK_OK, Gtk.ResponseType.OK))
    self.set_default_size(150, 100)
    if _name!=None and _service!=None:
      label=Gtk.Label("Shall service \""+_service+"\" of "+_server+"/"+_name+" be deleted?")
    elif _name!=None and _service==None:
      label=Gtk.Label("Shall name \""+_name+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()


normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE

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
  def __init__(self,_parent):
    Gtk.Grid.__init__(self)
    self.parent=_parent
    self.linkback=self.parent.linkback
    self.navbar=Gtk.Entry()
    self.navcontent=Gtk.ListStore(str)
    self.navbox=Gtk.TreeView(self.navcontent)
    self.navcontextsmall=Gtk.Label()
    self.navcontextmain=Gtk.Frame()
    self.navcontextmain.set_label("Context")

    navcontainer=Gtk.Grid()
    navcontainer.set_column_spacing(2)

    navcontainer.set_margin_top(2)
    navcontainer.set_margin_left(5)
    navcontainer.set_margin_right(5)
    temp1=Gtk.Label("Navigation: ")
    navcontainer.attach(temp1,0,0,1,1)
    navcontainer.attach(self.navbar,1,0,1,1)
    self.navbar.set_hexpand (True)

    self.attach(navcontainer,0,0,2,1)
    self.attach(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL),0,1,2,1)

    self.frame_nav=Gtk.Frame()
    self.frame_nav.add(self.navbox)
    self.frame_nav.set_margin_right(5)
    self.frame_nav.set_label_align(0.1,0.8)

    #self.attach(self.navcontextsmall,0,2,1,1)
    self.attach(self.frame_nav,0,2,1,1)

    
    self.navcontextmain.set_label_align(0.1,0.8)
    self.attach(self.navcontextmain,1,2,1,1)
    self.scnupdate()

  def scnupdate(self):
    if self.navbar.get_text()=="":
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      self.buildNonegui()
      return
    splitnavbar=self.navbar.get_text().split("/")
    if len(splitnavbar)==1:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      self.buildservergui(splitnavbar)
    elif len(splitnavbar)==2:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      self.buildnamegui(splitnavbar)
    elif len(splitnavbar)==3:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(0.7, 1, 0.7, 1))
      self.buildservicegui(splitnavbar)
    else:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()

  def buildNonegui(self):
    self.frame_nav.set_label("Server")
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 1, 1, 1))
    self.navcontent.clear()
    for elem in self.linkback.main.scn_servers.get_list():
      self.navcontent.append((elem[0],))
    


  def buildservergui(self,navelems):
    temp_names=self.linkback.main.scn_servers.get_names()
    if temp_names==None:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0.7, 0.7, 1))
    self.frame_nav.set_label("Name")
    self.navbar.set_text(navelems[0])
    self.navconinserttent.clear()
    for elem in temp_names:
      self.navcontent.append(elem[0])

  def buildnamegui(self,navelems):
    temp1=self.linkback.main.scn_servers.get_node(navelems[0])
    if temp1==None:
      self.navbar.override_background_color(normalflag, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return
    temp2=self.c_list_services(navelems[0],navelems[1])
    if temp2==None:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.frame_nav.set_label("Service")
    self.navbar.set_text(navelems[0]+"/"+navelems[1])
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem[0],))


  def buildservicegui(self,navelems):
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 0.7, 0.7, 1))
    self.frame_nav.set_label(None)
    self.navbar.set_text(navelems[0]+"/"+navelems[1]+"/"+navelems[2])
    self.navcontent.clear()

  def delete_server(self):
    temp=self.serverlist.get_selection().get_selected_rows()
    if temp==None:
      return 

    dialog = scnDeletionDialog(self.parent,temp[0])
    try:
      if dialog.run()==True:
        if self.parent.linkback.main.scn_servers.delete_node(self.name)==True:
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
      else:
        self.parent.state_widget.set_text("Aborted")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()

  def add_server(self,button):
    pass
    
  def edit_server(self,button):
    pass

  def update(self):
    pass
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

class scnPageFriends(Gtk.Frame):
  parent=None
  def __init__(self,_parent):
    Gtk.Frame.__init__(self)
    self.parent=_parent



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
    self.confirm_button=Gtk.Button("Apply")
    self.reset_button=Gtk.Button("Reset")


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

"""  app.run(host='localhost', port=8080, debug=True)

  client_interact_thread = threading.Thread(target=run(host='localhost', port=8080))
  client_interact_thread = True
  client_interact_thread.start()
  
  t.debug()"""

