#! /usr/bin/env python3

import sqlite3
import signal
import sys
import socketserver
import hashlib

from OpenSSL import SSL,crypto

from scn_base import sepm,sepc,sepu
from scn_base import scn_base_server,scn_send,scn_receive,printdebug,init_config_folder,check_certs,generate_certs

from scn_config import scn_server_port,default_config_folder,server_host





class scn_name_sql(object):
#  message=""
#  pub_cert=None
#  scn_services={"admin":[]}
  dbcon=None
  name=None

  def __init__(self,dbcon,_name):
    self.dbcon=dbcon
    self.name=_name

  def __del__(self):
    self.dbcon.close()
  def set_message(self,_message):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_name SET message=? WHERE name=?''', (_message,self.name))
      self.dbcon.commit()
    except Exception as u:
      printdebug(u)
      self.dbcon.rollback()
      return False
    return True
  def get_message(self):
    message=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT message FROM scn_name WHERE name=?''',(self.name,))
      message=cur.fetchone()
    except Exception as u:
      printdebug(u)
      return None
    return message
  def set_pub_cert(self,_cert):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_name SET pub_cert=? WHERE name=?''',(_cert,self.name))
      self.dbcon.commit()
    except Exception as u:
      printdebug(u)
      self.dbcon.rollback()
      return False
    return True
  def get_pub_cert(self):
    pub_cert=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT pub_cert FROM scn_name WHERE name=?''',(self.name,))
      pub_cert=cur.fetchone()
    except Exception as u:
      printdebug(u)
      return None
    return pub_cert

#=get_service
  def get(self,_servicename):
    ob=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT nodename,addrtype,addr,hashed_secret FROM scn_node WHERE scn_name=? AND servicename=?''',(self.name,_servicename))
      if cur.rowcount>0:
        ob=cur.fetchmany()
    except Exception as u:
      printdebug(u)
    return ob


#"admin" is admin
  def update_service(self,_servicename,_secrethashlist):
#max_service_nodes checked in body
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT nodeid FROM scn_node WHERE scn_name=? AND servicename=?''',(self.name,_servicename))
      a=len(_secrethashlist)
      b=cur.rowcount
      for c in range(0,max(a,b)):
        if c<a and c<b:
          cur.execute('''UPDATE scn_node SET nodename=?, hashed_secret=? WHERE scn_name=? AND servicename=? AND nodeid=? ''',(_secrethashlist[c][0],_secrethashlist[c][1], self.name,_servicename,c))
        elif c<a:
          cur.execute('''INSERT into scn_node values(?,?,?,'','',?)''', self.name,_servicename,c,_secrethashlist[c])
        elif c<b:
          cur.execute('''DELETE FROM scn_node WHERE scn_name=? AND servicename=? AND nodeid=?);''',(self.name,_servicename,c))
        self.dbcon.commit()
    except Exception as u:
      self.dbcon.rollback()
      printdebug(u)
      return False
    return True

#security related
  def verify_secret(self,_servicename,_secret):
    state=False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT addrtype,addr FROM scn_node WHERE scn_name=? AND servicename=? AND hashed_secret=?''',self.name,_servicename,hashlib.sha256(bytes(_secret)).hexdigest())
      if cur.rowcount>0:
        state=True
    except Exception as u:
      printdebug(u)
      state=False
    return state

  def update_secret(self,_servicename,_secret,_newsecret):
    if self.verify_secret(_servicename,_secret)==False:
      return False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_node SET hashed_secret=? WHERE servicename=? AND scn_name=? AND hashed_secret=?''',(hashlib.sha256(bytes(_newsecret)).hexdigest(),_servicename,self.name,hashlib.sha256(bytes(_secret)).hexdigest()))
      cur.commit()
    except Exception as u:
      printdebug(u)
      cur.rollback()
      return False
    return True

#auth with address ["",""]=unauth
#authorize before
  def auth(self,_servicename,_secret,_address):
    _secrethash=hashlib.sha256(bytes(_secret)).hexdigest()
    state=False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_node SET addrtype=?,addr=? WHERE scn_name=? AND servicename=? AND hashed_secret=?''',(_address[0],_address[1],self.name,_servicename,_secrethash))
      cur.commit()
    except Exception as u:
      printdebug(u)
      cur.rollback()
      state=False
    return state

class scn_name_list_sqlite(object):
  db_path=None
  def __init__(self, db):
    self.db_path=db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return
    try:
      con.execute('''CREATE TABLE if not exists scn_name(name TEXT, message TEXT, pub_cert BLOB  );''')
      con.commit()
    except Exception as u:
      printdebug(u)
      con.rollback()
    try:
      con.execute('''CREATE TABLE if not exists scn_node(scn_name TEXT,servicename TEXT,nodename TEXT, nodeid INTEGER, addrtype TEXT, addr TEXT, hashed_secret BLOB, PRIMARY KEY(scn_name,servicename,nodeid),FOREIGN KEY(scn_name) REFERENCES scn_name(name) ON UPDATE CASCADE ON DELETE CASCADE);''')
      con.commit()
    except Exception as u:
      printdebug(u)
      con.rollback()
    con.close()

  def get(self,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('SELECT name FROM scn_name WHERE name=?', (_name,))
      resultname=cur.fetchone()
      if resultname!=None:
        ob=scn_name_sql(con,resultname) 
    except Exception as u:
      printdebug(u)
    return ob

  def length(self, _name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(' SELECT DISTINCT servicename FROM scn_node WHERE scn_name=?', (_name,))
      length=cur.rowcount()
    except Exception as u:
      printdebug(u)
      length=0
    return length

  def del_name(self,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    state=True
    try:
      cur = con.cursor()
      #shouldn't throw error if not available
      cur.execute('''DELETE FROM scn_name WHERE name=?);''',(_name,))
      con.commit()
    except Exception:
      con.rollback()
      state=False
    finally:
      con.close()
    return state

  def create_name(self,_name,_secret):
    if self.contains(_name)==True:
      return None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      return None
    try:
      cur = con.cursor()
      cur.execute('''INSERT into scn_name(name,message,pub_cert) values(?,'',NULL)''', _name)
      cur.execute('''INSERT into scn_node
(scn_name,servicename,nodename,nodeid,addrtype,addr,hashed_secret)
values(?,admin,'init',0,'','',?)''', (_name,hashlib.sha256(bytes(_secret)).hexdigest()))
    except Exception as u:
      printdebug(u)
    
    return self.get(_name)

#secret should be machine generated


class scn_server(scn_base_server):
  is_active=True
  priv_cert=None
  pub_cert=None
  config_path=""
  actions={"register_name":scn_base_server.register_name,"delete_name":scn_base_server.delete_name,"update_cert":scn_base_server.update_cert,"update_message": scn_base_server.update_message,"update_service": scn_base_server.update_service,"delete_service":scn_base_server.delete_service,"get_service_secrethash": scn_base_server.get_service_secrethash,"serve": scn_base_server.serve_service,"unserve": scn_base_server.unserve_service,"update_secret": scn_base_server.update_secret,"use_special_service_auth": scn_base_server.use_special_service_auth,"use_special_service_unauth":scn_base_server.use_special_service_unauth,"get_name_message":scn_base_server.get_name_message,"get_name_cert":scn_base_server.get_name_cert,"get_server_cert":scn_base_server.get_server_cert,"info":scn_base_server.info}


  callback={}

  def __init__(self,_config_path,_name):
    self.version="1"
    self.name=_name
    self.config_path=_config_path
    init_config_folder(self.config_path)
    if check_certs(self.config_path+"scn_server_cert")==False:
      printdebug("private key not found. Generate new...")
      generate_certs(self.config_path+"scn_server_cert")
      printdebug("Finished")
    with open(self.config_path+"scn_server_cert"+".priv", 'rt') as readinprivkey:
      self.priv_cert=readinprivkey.read()
    with open(self.config_path+"scn_server_cert"+".pub", 'rt') as readinpubkey:
      self.pub_cert=readinpubkey.read()
    self.scn_names=scn_name_list_sqlite(self.config_path+"scn_server_db")
    self.special_services={"retrieve_callback": self.retrieve_callback,"auth_callback": self.auth_callback}
    self.special_services_unauth={"test":self.info ,"callback":self.callback}
    printdebug("Server init finished")

  def callback(self,_socket,_name,_store_name):
    if self.scn_names.contains(_name)==False:
      scn_send("error"+sepc+"name not exists"+sepm,_socket)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("ip",str(_socket.getpeername()[0])+sepu+str(_socket.getpeername()[1])),]
    scn_send( "success"+sepm,_socket)
  def tunnel_callback(self,_socket,_name,_store_name,_tunnelnumber):
    if self.scn_names.contains(_name)==False:
      scn_send("error"+sepc+"name not exists"+sepm,_socket)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("tunnel",_tunnelnumber),]
    scn_send( "success"+sepm,_socket)

  def auth_callback(self,_socket,_name,_store_name,_secret):
    if self.scn_names.contains(_name)==False or \
 self.service_auth(_store_name,"callback",_secret)==False \
or self.scn_names.contains(_store_name)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("name",_store_name),]
    scn_send("success"+sepm,_socket)
    
  def retrieve_callback(self,_socket,_name,_secret):
    if self.scn_names.contains(_name)==False or self.service_auth(_name,"callback",_secret)==False:
      scn_send("error"+sepc+"auth failed"+sepm,_socket)
      return
    temp=""
    for elem in self.callback[_name]:
      temp+=sepc+elem[0]+sepu+elem[1]
    scn_send("success"+temp+sepm,_socket)
    return 


class scn_server_handler(socketserver.BaseRequestHandler):
  linkback=None
  def setup(self):
    pass
  def handle(self):
    print("handler begin")
    self.request.settimeout(10)
    try:
      temp=scn_receive(self.request)
      if temp==None:
        scn_send("error"+sepc+"no input"+sepm,self.request)
      elif temp[0] in self.linkback.actions:
        try:
          self.linkback.actions[temp[0]](self.linkback,self.request,*temp[1:])
        except TypeError as e:
          scn_send("error"+sepc+"invalid number args"+sepm,self.request)
      else:
        scn_send("error"+sepc+"no such function"+sepm,self.request)
    except BrokenPipeError:
      pass
    except Exception as e:
      printdebug(e)
      

#socketserver.ThreadingMixIn, 
class scn_sock_server(socketserver.TCPServer):
  linkback=None
  def __init__(self, server_address, HandlerClass,_linkback):
    socketserver.TCPServer.__init__(self, server_address, HandlerClass)
    self.linkback=_linkback

    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    #temp_context.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM,self.linkback.priv_cert))
    #certs broken
    #temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,self.linkback.pub_cert))
    self.socket = SSL.Connection(temp_context,self.socket)
    self.socket.set_accept_state()
  def shutdown_request(self, request):
    """Called to shutdown and close an individual request."""
    try:
      #explicitly shutdown.  socket.close() merely releases
      #the socket and waits for GC to perform the actual close.
      request.shutdown()
    except OSError:
      pass #some platforms may raise ENOTCONN here
    self.close_request(request)

server=None

def signal_handler(signal, frame):
  #rec_pre.is_active=False
  #rec.is_active=False
#  server.shutdown()
  sys.exit(0)
if __name__ == "__main__":
  rec_pre = scn_server(default_config_folder,server_host+"_scn")
  rec = scn_server_handler
  rec.linkback=rec_pre
  
  # Create the server, binding to localhost on port 9999
  server = scn_sock_server((server_host, scn_server_port), rec,rec_pre) 
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
  printdebug("Server started")
