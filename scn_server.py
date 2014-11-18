#! /usr/bin/env python3

import sqlite3
import signal
import sys
import socketserver
import socket
import hashlib
import tempfile
import threading
#import time

from OpenSSL import SSL,crypto

from scn_base import sepm,sepc #,sepu
from scn_base import scn_base_server,scn_base_base,scn_socket,printdebug,printerror,init_config_folder,check_certs,generate_certs,interact

from scn_config import scn_server_port,default_config_folder,scn_host,max_channel_nodes
#,scn_cache_timeout


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
      con.execute('''CREATE TABLE if not exists addr_store(domain TEXT, channel TEXT, clientid INT, addr_type TEXT, addr TEXT, hashed_pub_cert TEXT, PRIMARY KEY(domain,channel,hashed_pub_cert));''')
      con.commit()
      con.close()
    except Exception as e:
      printerror(e)
      con.close()
      return

    try:
      con=sqlite3.connect(self.db_tmp)
      con.execute('''CREATE TABLE if not exists addr_store(domain TEXT, channel TEXT, clientid INT, addr_type TEXT, addr TEXT,hashed_pub_cert TEXT, PRIMARY KEY(domain,channel,hashed_pub_cert));''')
      
      con.commit()
      con.close()
    except Exception as e:
      printerror(e)
      con.close()
      return
    
  def det_con(self,_channel):
    if _channel[0]=="=" or _channel=="main" or _channel=="notify":
      return sqlite3.connect(self.db_tmp)
    #elif _channel=="store":
    #  return sqlite3.connect(self.db_pers)
    else:
      return sqlite3.connect(self.db_pers)
      #return None

  def get(self,_domain,_channel,_nodeid=None):
    nodelist=None
    con=self.det_con(_channel)
    try:
      cur = con.cursor()
      if _nodeid is None:
        cur.execute('''SELECT addr_type,addr,hashed_pub_cert
        FROM addr_store
        WHERE domain=? AND channel=?
        ORDER BY clientid ASC''',(_domain,_channel))
      else:
        cur.execute('''SELECT addr_type,addr,hashed_pub_cert
        FROM addr_store
        WHERE domain=? AND channel=? AND clientid=?''',(_domain,_channel,_nodeid))
      nodelist=cur.fetchall()
    except Exception as e:
      printerror(e)
      con.close()
      return None
    con.close()
    return nodelist

  def update(self,_domain,_channel,_nodeid,_pub_cert_hash,_addr_type,_addr):
    con=self.det_con(_channel)
    try:
      cur = con.cursor()
      #single entry
      if _channel[0]=="=" or _channel=="main":
        cur.execute('''DELETE FROM addr_store
        WHERE domain=? AND
        channel=?;''',(_domain, _channel))

        cur.execute('''INSERT into
        addr_store(domain,channel,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,0,?,?);''',
        (_domain,_channel, _pub_cert_hash, _addr_type, _addr))
      #order by activity
      elif _channel[0]=="+" or _channel=="notify":

        cur.execute('''UPDATE addr_store
        SET clientid = clientid+1
        WHERE domain=? AND
        channel=?;''',
        (_domain, _channel))

        cur.execute('''DELETE FROM addr_store
        WHERE domain=? AND
        channel=? AND
        nodeid>?;''',
        (_domain, _channel, max_channel_nodes))

        cur.execute('''INSERT into
        addr_store(domain,channel,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,0,?,?)''',
        (_domain,_channel, _pub_cert_hash, _addr_type, _addr))
      #order by nodeid (default)
      elif _channel[0]=="-" or True:
        cur.execute('''INSERT OR REPLACE into
        addr_store(domain,channel,clientid,hashed_pub_cert,addr_type, addr)
        values(?,?,?,?,?)''',
        (_domain,_channel, _nodeid, _pub_cert_hash, _addr_type, _addr))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_node(self,_domain,_channel,_pub_cert_hash):
    con=self.det_con(_channel)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE domain=? AND
      channel=? AND
      hashed_pub_cert=?;''',(_domain, _channel,_pub_cert_hash))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_channel(self,_domain,_channel):
    con=self.det_con(_channel)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE domain=? AND
      channel=?;''',(_domain, _channel))
    except Exception as e:
      printerror(e)
      con.close()
      return False
    con.close()
    return True

  def del_domain(self,_domain):
    con=sqlite3.connect(self.db_pers)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE domain=?;''',(_domain,))
    except Exception as e:
      con.close()
      printerror(e)
      return False
    con.close()
    con=sqlite3.connect(self.db_tmp)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE domain=?;''',(_domain,))
    except Exception as e:
      con.close()
      printerror(e)
      return False
    con.close()
    return True


class scn_domain_sql(object):
#  message=""
#  pub_cert=None
#  scn_channels={"admin":[]}
  dbcon=None
  domain=None

  def __init__(self,dbcon,_domain):
    self.dbcon=dbcon
    self.domain=_domain

  def __del__(self):
    self.dbcon.close()
  def set_message(self,_message):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_domain SET message=? WHERE name=?''', (_message,self.domain))
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
      cur.execute('''SELECT message FROM scn_domain WHERE name=?''',(self.domain,))
      message=cur.fetchone()
    except Exception as e:
      printerror(e)
      return None
    if message is not None:
      message=message[0]
    return message

  def get_channel(self,_channelname,_nodeid=None):
    ob=None
    try:
      cur = self.dbcon.cursor()
      if _nodeid is None:
        cur.execute('''SELECT nodeid,nodename,hashed_secret,hashed_pub_cert
        FROM scn_node WHERE scn_domain=? AND channelname=?
        ORDER BY nodeid ASC;''',(self.domain,_channelname))
      else:
        cur.execute('''SELECT nodeid,nodename,hashed_pub_cert,hashed_secret
        FROM scn_node WHERE scn_domain=? AND channelname=? AND nodeid=?;''',(self.domain,_channelname,_nodeid))

      ob=cur.fetchall()
    except Exception as e:
      printerror(e)
    if ob==[]:
      return None
    else:
      return ob #nodeid,nodename,hashed_pub_cert,hashed_secret

    
  def list_channels(self):
    ob=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT channelname
      FROM scn_node WHERE scn_domain=?
      ORDER BY channelname ASC;''',(self.domain,))
      ob=cur.fetchall()
    except Exception as e:
      printerror(e)
    return ob #channelname
  
  
  def length(self, _channel):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(''' SELECT nodeid
      FROM scn_node WHERE scn_domain=? AND channelname=? ''', (self.domain,_channel))
      length=len(cur.fetchall())
    except Exception as e:
      printerror(e)
      length=0
    return length

  def get_cert(self,_channelname,_secret_hash):
    ob=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT hashed_pub_cert
      FROM scn_node
      WHERE scn_domain=? AND channelname=? AND hashed_pub_cert=?''',(self.domain,_channelname,_secret_hash))
      ob=cur.fetchone()
    except Exception as e:
      printerror(e)
    #strip tupel
    if ob is not None:
      ob=ob[0]
    return ob #hashed_pub_cert

  
  #"admin" is admin
  def update_channel(self,_channelname,_secrethashlist):
  #max_channel_nodes checked in body
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT nodeid FROM scn_node WHERE scn_domain=? AND channelname=?''',(self.domain,_channelname))
      a=len(_secrethashlist)
      b=cur.rowcount
      for c in range(0,max(a,b)):
        if c<=a:
          cur.execute('''INSERT OR REPLACE into
          scn_node(scn_domain,channelname, nodeid, nodename, hashed_pub_cert, hashed_secret)
          values(?,?,?,?,?,?);''',
          (self.domain,_channelname,c,_secrethashlist[c][0],_secrethashlist[c][1],_secrethashlist[c][2]))
        elif c<b:
          cur.execute('''DELETE FROM scn_node WHERE scn_domain=? AND channelname=? AND nodeid=?;''',(self.domain,_channelname,c))
      self.dbcon.commit()
    except Exception as e:
      self.dbcon.rollback()
      printerror(e)
      return False
    return True

  def delete_channel(self,_channelname):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''DELETE FROM scn_node WHERE scn_domain=? AND channelname=?;''',(self.domain,_channelname))
      self.dbcon.commit()
    except Exception as e:
      printerror(e)
      return False
    return True
  
  #security related
  #_secret should be already bytes
  def verify_secret(self,_channelname,_secret):
    state=False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT scn_domain FROM scn_node WHERE scn_domain=? AND channelname=? AND hashed_secret=?;''',(self.domain,_channelname,hashlib.sha256(_secret).hexdigest()))
      if cur.fetchone() is not None:
        state=True
    except Exception as e:
      printerror(e)
      state=False
    return state

  #_secret should be already bytes
  def update_secret(self,_channelname,_secret,_newsecret_hash,_pub_cert_hash=None):
    if self.verify_secret(_channelname,_secret)==False:
      return False
    try:
      cur = self.dbcon.cursor()
      if _pub_cert_hash is not None:
        cur.execute('''UPDATE scn_node SET hashed_secret=?, hashed_pub_cert=? WHERE channelname=? AND scn_domain=? AND hashed_secret=?;''',(_newsecret_hash,_pub_cert_hash,_channelname,self.domain,hashlib.sha256(_secret).hexdigest()))
      else:
        cur.execute('''UPDATE scn_node SET hashed_secret=? WHERE channelname=? AND scn_domain=? AND hashed_secret=?;''',(_newsecret_hash,_channelname,self.domain,hashlib.sha256(_secret).hexdigest()))
      self.dbcon.commit()
    except Exception as e:
      cur.rollback()
      printerror(e)
      return False
    return True

  def delete_secret(self,_channelname,_secret):
    if self.verify_secret(_channelname,_secret)==False:
      return False
    try:
      cur = self.dbcon.cursor()
      cur.execute('''DELETE FROM scn_node WHERE channelname=? AND scn_domain=? AND hashed_secret=?;''',(_channelname,self.domain,hashlib.sha256(bytes(_secret)).hexdigest()))
      self.dbcon.commit()
    except Exception as e:
      cur.rollback()
      printerror(e)
      return False
    return True

class scn_domain_list_sqlite(object):
  db_path=None
  def __init__(self, db):
    self.db_path=db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return
    try:
      con.execute('''CREATE TABLE if not exists scn_domain(name TEXT, message TEXT);''')
      con.commit()

      con.execute('''CREATE TABLE if not exists scn_node(scn_domain TEXT,channelname TEXT, nodeid INTEGER, nodename TEXT, hashed_pub_cert TEXT, hashed_secret TEXT, PRIMARY KEY(scn_domain,channelname,nodeid),FOREIGN KEY(scn_domain) REFERENCES scn_domain(name) ON UPDATE CASCADE ON DELETE CASCADE);''')
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
    con.close()

  def get(self,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('SELECT name FROM scn_domain WHERE name=?', (_domain,))
      resultname=cur.fetchone()
      if resultname is not None:
        ob=scn_domain_sql(con,resultname[0]) 
    except Exception as e:
      printerror(e)
    return ob
  
  def list_domains(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('''
      SELECT name FROM scn_domain
      ORDER BY name ASC''')
      ob=cur.fetchall()
    except Exception as e:
      printerror(e)
    return ob

  def length(self, _domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(''' SELECT DISTINCT channelname
      FROM scn_node WHERE scn_domain=?''', (_domain,))
      length=cur.rowcount
    except Exception as e:
      printerror(e)
      length=0
    return length

  def del_domain(self,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return False
    if self.get(_domain) is None:
      printdebug("Deletion of non-existent domain")
      return True
    state=True
    try:
      cur = con.cursor()
      #shouldn't throw error if not available
      cur.execute('''DELETE FROM scn_domain WHERE name=?;''',(_domain,))
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
      state=False
    con.close()
    return state

  def create_domain(self,_domain,_secrethash,_certhash):
    if self.get(_domain) is not None:
      return None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      printerror(e)
      return None
    try:
      cur = con.cursor()
      cur.execute('''INSERT into scn_node
      (scn_domain,channelname,nodeid,nodename,hashed_secret,hashed_pub_cert)
      values(?,'admin',0, ?,?,?)''', (_domain,'domainadmin',_secrethash,_certhash))
      cur.execute('''INSERT into scn_domain(name,message) values(?,'')''', (_domain,))
      con.commit()
    except Exception as e:
      con.rollback()
      printerror(e)
    return self.get(_domain)



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
           "serve": scn_base_server.s_serve_channel,
           "unserve": scn_base_server.s_unserve_channel,
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
      printdebug("Certificate(s) not found. Generate new...")
      generate_certs(self.config_path+"scn_server_cert")
      printdebug("Certificate generation complete")
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
        printdebug("Socket closed") 
        break
      except SSL.SysCallError as e:
        if e.args[0]==104 or e.args[0]==-1:
          #"104: ECONNRESET, -1: Unexpected EOF"
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
      printerror("Exception while shutdown")
      printerror(e)
    self.close_request(request)

  def close_request(self,request):
    if request is None:
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
