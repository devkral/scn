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
#import bottle

#app=bottle.Bottle()
#from bottle import template,static_file
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
    return temp #serverurl,cert

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
      cur.execute('''SELECT nodename FROM scn_certs''')
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #serverurl,cert

  def get_next(self):
    self.view_cur+=1
    return self.view_list[self.view_cur] #serverurl,cert,name,secret,pendingstate
  def rewind(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT b.url,b.cert,a.name,a.secret,a.pending
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

    self.scn_servs=scn_servs_sql(self.config_path+"scn_client_server_db")
    self.scn_friends=scn_friends_sql(self.config_path+"scn_client_friend_db")

#connect methods
  def connect_to(self,_servername):
    tempdata=self.scn_servs.get_node(_servername)
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
  
  def get_list(self):
    return self.scn_servs.get_list()

  def get_node(self,_nodename):
    return self.scn_servs.get_node(_nodename)

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
                        "addserver": scn_base_client.c_add_node,
                        "updserver": scn_base_client.c_update_node, 
                        "delserver": scn_base_client.c_delete_node}
  clientactions_list = {"getservicehash": scn_base_client.c_get_service_secrethash, 
                        "getmessage": scn_base_client.c_get_name_message, 
                        "getservercert": scn_base_client.c_get_server_cert, 
                        "info": scn_base_client.c_info, 
                        "getlist": get_list, 
                        "getnode": get_node}

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
          printerror(e)
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

"""
scn_client_node=None


@app.route('/server/<server>')
@app.route('/server/<server>/<name>')
@app.route('/server/<server>/<name>/<service>')
@app.route('/server')
@app.route('/')
def generate_server_nav(server=None,name=None,service=None):
  if "Klsls" in scn_client_node.clientactions_bool:
    scn_client_node.c_info(server)
    return template("server_nav",server=server,name=name,service=service,return_state=None,return_list=None)
  elif "Klsls" in scn_client_node.clientactions_list:
    scn_client_node.c_info(server)
    return template("server_nav",server=server,name=name,service=service,return_state=None,return_list=None)
  else:
    return template("server_nav",server=server,name=name,service=service,return_state=None,return_list=None)


@app.route('/friends/<node>')
@app.route('/friends')
def generate_client_nav(node=None):
  return template("client_nav",node=node,return_state=None,return_list=None)

@app.route('/actions/<action>')
def do_action(action):
  pass

@app.route('/static/:path#.+#')
def server_static(path):
    return static_file(path, root=curdir+'/static')


#def do_action(action,server):
#    return template('<b>Hello {{name}}</b>!', name=name)
"""



class scnGUI(Gtk.Window):
  s_confirm_button_id=None
  s_reset_button_id=None
  f_confirm_button_id=None
  f_reset_button_id=None
  linkback=None
  def __init__(self,_linkback):
    Gtk.Window.__init__(self, title="Secure Node Communication")
    self.linkback=_linkback
    self.resize(600,200)
    

    self.state_widget=Gtk.Label(label="")
    
    add_server=Gtk.Button(label="Add server")
    add_server.connect("clicked", self.server_add_gen)
    delete_server=Gtk.Button(label="Delete server")
    delete_server.connect("clicked", self.on_button_clicked)
    #    self.rename_server=Gtk.Button(label="Rename server")
    info_server=Gtk.Button(label="Retrieve server info")
    info_server.connect("clicked", self.on_button_clicked)


    self.servers=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    self.server_controls=Gtk.Grid()
    self.server_controls.set_column_spacing(10)
    self.server_controls.set_row_spacing(2)
    self.s_confirm_button=Gtk.Button(label="Apply")
    self.s_confirm_button.set_margin_top(5)
    #self.s_confirm_button.set_margin_bottom(5)
    self.s_reset_button=Gtk.Button(label="Reset")
    self.s_reset_button.set_margin_top(5)
    self.server_controls.set_margin_top(5)
    self.server_controls.set_margin_bottom(5)

    self.server_controls.attach( add_server, 0, 0, 2, 1)
    self.server_controls.attach( delete_server, 0, 1, 2, 1)
    self.server_controls.attach( info_server, 0, 2, 2, 1)
    self.server_controls.attach( self.s_reset_button, 0, 3, 1, 1)
    self.server_controls.attach( self.s_confirm_button, 1, 3, 1, 1)
    self.server_frame=Gtk.Frame()
    
    self.servers.pack_start(self.server_controls,False,False,5)
    self.servers.pack_start(self.server_frame,True,True,5)

    add_friend=Gtk.Button(label="Add friend")
    add_friend.connect("clicked", self.on_button_clicked)
    delete_friend=Gtk.Button(label="Delete friend")
    delete_friend.connect("clicked", self.on_button_clicked)

    self.friends=Gtk.Box()
    self.friend_controls=Gtk.Grid()
    #.set_margin_left(5)
    self.f_confirm_button=Gtk.Button(label="Apply")
    self.f_reset_button=Gtk.Button(label="Reset")
    
    #self.friends.set_margin_left(5)
    self.friend_controls.attach( add_friend ,0,0,1,1)
    self.friend_controls.attach( delete_friend ,0,1,1,1)
    self.friends.pack_start(self.friend_controls,False,False,5)
    self.friend_frame=Gtk.Frame()
    

    self.main_contain=Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    #self.main_grid.set_column_spacing(10)
    #self.main_grid.set_row_spacing(20)
    self.friend_server_switch=Gtk.Notebook()
    self.friend_server_switch.append_page(self.servers,Gtk.Label("Servers"))
    self.friend_server_switch.append_page(self.friends,Gtk.Label("Friends"))
    
    self.main_contain.pack_start(self.friend_server_switch,True,True,2)
    #self.main_contain.attach(self.friend_server_switch,0,0,1,1)
    #self.main_grid.set_vexpand_set(True)
    #self.main_grid.set_hexpand_set(True)
#    self.main_contain.set_margin_left(5)
#    self.main_contain.set_margin_right(2)
    #self.main_grid.attach(self.confirm_button,0,1,1,1)
    #self.main_grid.attach(self.reset_button,1,1,1,1)
    self.main_contain.pack_start(self.state_widget,True,True,10)#(self.state_widget,0,1,1,1)
    self.add(self.main_contain)

  def server_add_confirm(self,l):
    temp_container=self.server_frame.get_child()
    _name=temp_container.get_child_at(1,0).get_text()
    _url=temp_container.get_child_at(1,1).get_text()
    if _name=="":
      self.state_widget.set_label("Error: missing name")
      return
    if _url=="":
      self.state_widget.set_label("Error: missing url")
      return
    if self.linkback.main.c_add_node(_name,_url)==True:
      self.state_widget.set_label("Success")
    else:
      self.state_widget.set_label("An error happened")

  def server_add_gen(self,l):
    temp=self.server_frame.get_child()
    if temp!=None:
      temp.destroy()
    if self.s_confirm_button_id!=None:
      self.s_confirm_button.disconnect(self.s_confirm_button_id)
    if self.s_reset_button_id!=None:
      self.s_reset_button.disconnect(self.s_reset_button_id)
    self.state_widget.set_label("Ready")
    a=Gtk.Grid()
    a.attach(Gtk.Label("Name:"),0,0,1,1)
    a.attach(Gtk.Entry(),1,0,1,1)
    a.attach(Gtk.Label("IP/URL:"),0,1,1,1)
    a.attach(Gtk.Entry(),1,1,1,1)
    self.server_frame.add(a)
    self.server_frame.show_all()
    self.s_confirm_button_id = self.s_confirm_button.connect("clicked", self.server_add_confirm)
    self.s_reset_button_id = self.s_reset_button.connect("clicked", self.server_add_gen)
    
    
  def on_button_clicked(self, widget):
    print("Hello World")


win=None

def signal_handler(_signal, frame):
  #win.close()
  Gtk.main_quit()
  #app.close()
  #sys.exit(0)

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

