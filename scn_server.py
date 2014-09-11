#! /usr/bin/env python3

import sqlite3
import signal
import sys
import socketserver
import socket
import hashlib
import tempfile

from OpenSSL import SSL,crypto

from scn_base import sepm,sepc #,sepu
from scn_base import scn_base_server,scn_base_base,scn_socket,printdebug,printerror,init_config_folder,check_certs,generate_certs

from scn_config import scn_server_port,default_config_folder,scn_host,max_service_nodes


class scn_ip_store(object):
  db_pers=None
  db_tmp=None
  db_temp_keep_alive=None
  def __init__(self,dbpers):
    self.db_pers=dbpers
    self.db_temp_keep_alive=tempfile.NamedTemporaryFile()
    self.db_tmp=self.db_temp_keep_alive.name
    try:
      con=sqlite3.connect(self.db_pers)
      con.execute('''CREATE TABLE if not exists addr_store(name TEXT, service TEXT, clientid INT, addr_type TEXT, addr TEXT, hashed_pub_cert TEXT, PRIMARY KEY(name,service,hashed_pub_cert));''')
      con.commit()
      con.close()
    except Exception as e:
      printerror(e)
      con.close()
      return

    try:
      con=sqlite3.connect(self.db_tmp)
      con.execute('''CREATE TABLE if not exists addr_store(name TEXT, service TEXT, clientid INT, addr_type TEXT, addr TEXT,hashed_pub_cert TEXT, PRIMARY KEY(name,service,hashed_pub_cert));''')
      
      con.commit()
      con.close()
    except Exception as e:
      printerror(e)
      con.close()
      return
    
  
  def det_con(self,_service):
    if _service=="main" or _service=="notify":
      return sqlite3.connect(self.db_tmp)
    elif _service=="store":
      return sqlite3.connect(self.db_pers)
    else:
      return None

  def get(self,_name,_service,):
    nodelist=None
    con=self.det_con(_service)
    try:
      cur = con.cursor()
      cur.execute('''SELECT addr_type,addr,hashed_pub_cert
      FROM addr_store
      WHERE name=? AND service=? ORDER BY clientid''',(_name,_service))
      nodelist=cur.fetchmany()
    except Exception as e:
      printerror(e)
      con.close()
      return None
    con.close()
    return nodelist


  def update(self,_name,_service,_nodeid,_pub_cert_hash,_addr_type,_addr):
    con=self.det_con(_service)
    try:
      cur = con.cursor()
      #single entry
      if _service[0]=="=" or _service=="main":
        cur.execute('''DELETE FROM addr_store
        WHERE name=? AND
        service=?;''',(_name, _service))

        cur.execute('''INSERT into
        addr_store(name,service,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,0,?,?);''',
        (_name,_service, _pub_cert_hash, _addr_type, _addr))
      #order by activity
      elif _service[0]=="+" or _service=="notify":

        cur.execute('''UPDATE addr_store
        SET clientid = clientid+1
        WHERE name=? AND
        service=?;''',
        (_name, _service))

        cur.execute('''DELETE FROM addr_store
        WHERE name=? AND
        service=? AND
        nodeid>?;''',
        (_name, _service, max_service_nodes))

        cur.execute('''INSERT into
        addr_store(name,service,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,0,?,?)''',
        (_name,_service, _pub_cert_hash, _addr_type, _addr))
      #order by nodeid (default)
      elif _service[0]=="-" or True:
        cur.execute('''INSERT OR REPLACE into
        addr_store(name,service,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,?,?,?)''',
        (_name,_service, _nodeid, _pub_cert_hash, _addr_type, _addr))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_node(self,_name,_service,_pub_cert_hash):
    con=self.det_con(_service)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE name=? AND
      service=? AND
      hashed_pub_cert=?;''',(_name, _service,_pub_cert_hash))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_service(self,_name,_service):
    con=self.det_con(_service)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE name=? AND
      service=?;''',(_name, _service))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_name(self,_name):
    con=sqlite3.connect(self.db_pers)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE name=?;''',(_name))
    except Exception as e:
      con.close()
      printerror(e)
      return False
    con.close()
    con=sqlite3.connect(self.db_tmp)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE name=?;''',(_name))
    except Exception as e:
      con.close()
      printerror(e)
      return False
    con.close()
    return True


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
    except Exception as e:
      self.dbcon.rollback()
      printerror(e)
      return False
    return True
  def get_message(self):
    message=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT message FROM scn_name WHERE name=?''',(self.name,))
      message=cur.fetchone()
    except Exception as e:
      printerror(e)
      return None
    return message

#=get_service
  def get_service(self,_servicename,_nodeid=None):
    ob=None
    try:
      cur = self.dbcon.cursor()
      if _nodeid==None:
        cur.execute('''SELECT nodeid,nodename,hashed_secret,hashed_pub_cert
        FROM scn_node WHERE scn_name=? AND servicename=?
        ORDER BY nodeid''',(self.name,_servicename))
      else:
        cur.execute('''SELECT nodeid,nodename,hashed_pub_cert,hashed_secret
        FROM scn_node WHERE scn_name=? AND servicename=? AND nodeid=?''',(self.name,_servicename,_nodeid))

      ob=cur.fetchmany()
    except Exception as e:
      printerror(e)
    return ob #nodeid,nodename,hashed_pub_cert,hashed_secret

  def list_services(self):
    ob=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT servicename
      FROM scn_node WHERE scn_name=?''',(self.name,))
      ob=cur.fetchmany()
    except Exception as e:
      printerror(e)
    return ob #servicename

  def get_cert(self,_servicename,_secret_hash):
    ob=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT hashed_pub_cert
      FROM scn_node WHERE scn_name=? AND servicename=? AND hashed_pub_cert=?''',(self.name,_servicename,_secret_hash))

      ob=cur.fetchone()
    except Exception as e:
      printerror(e)
    return ob #hashed_pub_cert

#"admin" is admin
  def update_service(self,_servicename,_secrethashlist):
#max_service_nodes checked in body
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT nodeid FROM scn_node WHERE scn_name=? AND servicename=?''',(self.name,_servicename))
      a=len(_secrethashlist)
      b=cur.rowcount
      for c in range(0,max(a,b)):
        if c<=a:
          cur.execute('''INSERT OR REPLACE into
          scn_node(scn_name,servicename, nodeid, nodename, hashed_pub_cert, hashed_secret)
          values(?,?,?,?,?,?);''',
          self.name,_servicename,c,_secrethashlist[c][0],_secrethashlist[c][1],_secrethashlist[c][2])
        elif c<b:
          cur.execute('''DELETE FROM scn_node WHERE scn_name=? AND servicename=? AND nodeid=?;''',(self.name,_servicename,c))
      self.dbcon.commit()
    except Exception as e:
      self.dbcon.rollback()
      printerror(e)
      return False
    return True

  #security related
  #_secret should be already bytes
  def verify_secret(self,_servicename,_secret):
    state=False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT scn_name FROM scn_node WHERE scn_name=? AND servicename=? AND hashed_secret=?;''',(self.name,_servicename,hashlib.sha256(_secret).hexdigest()))
      if cur.fetchone()!=None:
        state=True
    except Exception as e:
      printerror(e)
      state=False
    return state

  #_secret should be already bytes
  def update_secret(self,_servicename,_secret,_newsecret_hash,_pub_cert_hash=None):
    if self.verify_secret(_servicename,_secret)==False:
      return False
    try:
      cur = self.dbcon.cursor()
      if _pub_cert_hash!=None:
        cur.execute('''UPDATE scn_node SET hashed_secret=?, hashed_pub_cert=? WHERE servicename=? AND scn_name=? AND hashed_secret=?;''',(_newsecret_hash,_pub_cert_hash,_servicename,self.name,hashlib.sha256(_secret).hexdigest()))
      else:
        cur.execute('''UPDATE scn_node SET hashed_secret=? WHERE servicename=? AND scn_name=? AND hashed_secret=?;''',(_newsecret_hash,_servicename,self.name,hashlib.sha256(_secret).hexdigest()))
      self.dbcon.commit()
    except Exception as e:
      cur.rollback()
      printerror(e)
      return False
    return True

  def delete_secret(self,_servicename,_secret):
    if self.verify_secret(_servicename,_secret)==False:
      return False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''DELETE FROM scn_node WHERE servicename=? AND scn_name=? AND hashed_secret=?;''',(_servicename,self.name,hashlib.sha256(bytes(_secret)).hexdigest()))
      self.dbcon.commit()
    except Exception as e:
      cur.rollback()
      printerror(e)
      return False
    return True

class scn_name_list_sqlite(object):
  db_path=None
  def __init__(self, db):
    self.db_path=db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return
    try:
      con.execute('''CREATE TABLE if not exists scn_name(name TEXT, message TEXT);''')
      con.commit()

      con.execute('''CREATE TABLE if not exists scn_node(scn_name TEXT,servicename TEXT, nodeid INTEGER, nodename TEXT, hashed_pub_cert TEXT, hashed_secret TEXT, PRIMARY KEY(scn_name,servicename,nodeid),FOREIGN KEY(scn_name) REFERENCES scn_name(name) ON UPDATE CASCADE ON DELETE CASCADE);''')
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
    con.close()

  def get(self,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('SELECT name FROM scn_name WHERE name=?', (_name,))
      resultname=cur.fetchone()
      if resultname!=None:
        ob=scn_name_sql(con,resultname[0]) 
    except Exception as e:
      printerror(e)
    return ob
  def list_names(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('SELECT name FROM scn_name')
      ob=cur.fetchmany()
    except Exception as e:
      printerror(e)
    return ob

  def length(self, _name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(' SELECT DISTINCT servicename FROM scn_node WHERE scn_name=?', (_name,))
      length=cur.rowcount
    except Exception as e:
      printerror(e)
      length=0
    return length

  def del_name(self,_name):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return False
    if self.get(_name)==None:
      printdebug("Deletion of non-existent name")
      return True
    state=True
    try:
      cur = con.cursor()
      #shouldn't throw error if not available
      cur.execute('''DELETE FROM scn_name WHERE name=?);''',(_name,))
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
      state=False
    con.close()
    return state

  def create_name(self,_name,_secrethash,_certhash):
    if self.get(_name)!=None:
      return None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    try:
      cur = con.cursor()
      cur.execute('''INSERT into scn_name(name,message) values(?,'')''', (_name,))
      cur.execute('''INSERT into scn_node
      (scn_name,servicename,nodeid,nodename,hashed_secret,hashed_pub_cert)
      values(?,'admin',0, 'init',?,?)''', (_name,_secrethash,_certhash))
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
    return self.get(_name)

#secret should be machine generated


class scn_server(scn_base_server):
  is_active=True
  server_context=None
  config_path=""
  actions={"register_name": scn_base_server.s_register_name,
           "delete_name": scn_base_server.s_delete_name,
           "update_message": scn_base_server.s_update_message,
           "add_service": scn_base_server.s_add_service,
           "update_service": scn_base_server.s_update_service,
           "delete_service":scn_base_server.s_delete_service,
           "get_service_secrethash": scn_base_server.s_get_service_secrethash,
           "serve": scn_base_server.s_serve_service,
           "unserve": scn_base_server.s_unserve_service,
           "update_secret": scn_base_server.s_update_secret,
           "use_special_service_auth": scn_base_server.s_use_special_service_auth,
           "use_special_service_unauth":scn_base_server.s_use_special_service_unauth,
           "get_name_message":scn_base_server.s_get_name_message,
           "get_cert":scn_base_base.s_get_cert,
           "info":scn_base_base.s_info,
           "pong":scn_base_base.pong}


  callback={}

  def __init__(self,_config_path,_name):
    self.version="1"
    self.name=_name
    self.config_path=_config_path
    init_config_folder(self.config_path)
    if check_certs(self.config_path+"scn_server_cert")==False:
      printdebug("Certificate(s) not found. Generate new...")
      generate_certs(self.config_path+"scn_server_cert")
      printdebug("Certificate generation complete")
    with open(self.config_path+"scn_server_cert"+".priv", 'rb') as readinprivkey:
      self.priv_cert=readinprivkey.read()
    with open(self.config_path+"scn_server_cert"+".pub", 'rb') as readinpubkey:
      self.pub_cert=readinpubkey.read()
    self.scn_names=scn_name_list_sqlite(self.config_path+"scn_server_name_db")
    self.scn_store=scn_ip_store(self.config_path+"scn_server_pers_id_db")
    #self.special_services={"retrieve_callback": self.retrieve_callback,"auth_callback": self.auth_callback}
    #self.special_services_unauth={"test":self.s_info ,"callback":self.callback}

    printdebug("Server init finished")

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
 self.service_auth(_store_name,"callback",_secret)==False \
or self.scn_names.contains(_store_name)==False:
      _socket.send("error"+sepc+"auth failed"+sepm)
      return
    if _name not in self.callback:
      self.callback[_name]=[]
    self.callback[_name]+=[("name",_store_name),]
    _socket.send("success"+sepm)
    
  def retrieve_callback(self,_socket,_name,_secret):
    if self.scn_names.contains(_name)==False or self.service_auth(_name,"callback",_secret)==False:
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
        if temp==None:
          sc.send("error"+sepc+"no input"+sepm)
          break
        elif temp in self.linkback.actions:
          self.linkback.actions[temp](self.linkback,sc)
        else:
          sc.send("error"+sepc+temp+": no such function"+sepm)
      except BrokenPipeError:
        printdebug("Socket closed") 
        break
      except SSL.SysCallError as e:
        if e.args[1]=="ECONNRESET" or e.args[1]=="Unexpected EOF":
          printdebug("Socket closed")
        else:
          printerror(e)
        break
      except Exception as e:
        printerror(e)
        break

#socketserver.ThreadingMixIn, 
class scn_sock_server(socketserver.TCPServer):
  linkback=None
  def __init__(self, server_address, HandlerClass,_linkback):
    socketserver.BaseServer.__init__(self, server_address, HandlerClass)
    self.linkback=_linkback

    temp_context = SSL.Context(SSL.TLSv1_2_METHOD)
    temp_context.set_options(SSL.OP_NO_COMPRESSION) #compression insecure (or already fixed??)
    temp_context.set_cipher_list("HIGH")
    temp_context.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM,self.linkback.priv_cert))
    temp_context.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM,self.linkback.pub_cert))
    self.socket = SSL.Connection(temp_context,socket.socket(self.address_family, self.socket_type))
    #self.socket.set_accept_state()
    self.server_bind()
    self.server_activate()


  def shutdown_request(self, request):
    if request==None:
      return
    try:
      #explicitly shutdown.  socket.close() merely releases
      #the socket and waits for GC to perform the actual close.
      request.shutdown()
    except (OSError):
      pass #some platforms may raise ENOTCONN here
    except Exception as e:
      printerror("Exception while shutdown")
      printerror(e)
    self.close_request(request)

  def close_request(self,request):
    if request==None:
      return
    try:
      request.close()
    except Exception as e:
      printerror(e)

server=None

def signal_handler(signal, frame):
  #rec_pre.is_active=False
  #rec.is_active=False
#  server.shutdown()
  sys.exit(0)
if __name__ == "__main__":
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
  printdebug("Server closed")
