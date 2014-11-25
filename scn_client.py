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


curdir=os.path.dirname(__file__)

class client_master(object):
  receiver=None
  main=None
cm=client_master()


#scn_servs: _channelname: _server,_domain:secret
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
      scn_friends_server(friendname TEXT, servername TEXT, domain TEXT,
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



  def update_server(self,_friendname,_servername,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT OR REPLACE into scn_friends_server(friendname,servername,domain) values(?,?,?);''',(_friendname,_servername,_domain))
      
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


#scn_servs: _channelname: _server,_name:secret
class scn_servs_sql(object):
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
      scn_serves(servername TEXT, domain TEXT, channel TEXT,
      secret BLOB, pending BOOLEAN,PRIMARY KEY(servername,domain,channel),
      FOREIGN KEY(servername) REFERENCES scn_urls(servername) ON UPDATE CASCADE ON DELETE CASCADE);''')


      con.execute('''CREATE TABLE if not exists scn_urls(servername TEXT, url TEXT, certname TEXT,
      PRIMARY KEY(servername,url,certname),
      FOREIGN KEY(certname) REFERENCES scn_certs(certname) ON UPDATE CASCADE ON DELETE CASCADE  );''')
      
      con.execute('''CREATE TABLE if not exists scn_certs(name TEXT, cert BLOB,PRIMARY KEY(name), UNIQUE(cert)  );''')

      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
    con.close()

  def add_server(self,_servername,_url,_cert,_certname=None):
    #ignore cert name if cert is already in db
    tcertname=self.get_cert_name(_cert)
    if tcertname is not None:
      _certname=tcertname
    if _certname is None:
      _certname=_servername

    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      if tcertname is None:
        cur.execute('''INSERT into scn_certs(name,cert) values (?,?);''',(_certname,_cert))
      cur.execute('''INSERT into scn_urls(servername,url,certname) values(?,?,?);''',(_servername,_url,_certname))
      
      con.commit()
    except sqlite3.IntegrityError:
      printdebug("exists already")
      con.rollback()
      return False
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_server(self,_servername,_url,_cert):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''
      UPDATE scn_urls SET url=?
      WHERE servername=?;''',(_url,_servername))
      
      cur.execute('''
      UPDATE scn_certs SET cert=?
      WHERE name=(SELECT certname FROM scn_urls WHERE servername=?) ;''',(_cert,_servername))
#      if _certname_new is not None:
#        cur.execute('''
#        UPDATE scn_certs(certname) values(?)
#      WHERE certname=(SELECT certname FROM scn_urls WHERE servername=?) ;'''#,(_certname_new,_servername))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True


  def update_server_name(self,_servername,_servername_new):
    if self.get_server(_servername_new) is not None:
      return False
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_urls SET servername=? WHERE servername=?;''',(_servername_new,_servername))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_cert_name(self,_certname,_certname_new):
    if self.get_cert(_certname_new) is not None:
      return False
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_certs SET name=? WHERE name=?;''',(_certname_new,_certname))
      cur.execute('''UPDATE scn_urls SET certname=? WHERE certname=?;''',(_certname_new,_certname)) #why does the constraint not work?
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def change_cert(self,_servername,_certname_new):
    if self.get_cert(_certname_new) is None:
      return False
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_urls SET certname=? WHERE servername=?;''',(_certname_new,_servername))
      con.commit();
    except Exception as u:
      printdebug(u)
      con.rollback()
      return False
    con.close()
    return True

  def add_serve(self,_servername,_domain,_channel,_secret,_pendingstate=True):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT into scn_serves(
      servername,
      domain,
      channel,
      secret, pending)
      values (?,?,?,?,?)''',(_servername,_domain,_channel,_secret,_pendingstate))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def update_serve(self,_servername,_domain,_channel,_secret):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_serves SET secret=?
      WHERE
      servername=? AND
      domain=? AND
      channel=?;''',(_secret,_servername,_domain,_channel))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True
  
  def update_channel_pendingstate(self,_servername,_domain,_channel,_pendingstate=False):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_serves SET pending=? WHERE
      servername=? AND domain=? AND channel=?;
      ''',(_pendingstate,_servername,_domain,_channel))
      con.commit();
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True

  def list_domains(self,_servername,_channel=None,_pending=None):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      if _channel is None:
        cur.execute('''SELECT domain
        FROM scn_serves
        WHERE servername=?;''',(_servername,))
      elif _pending is None:
        cur.execute('''SELECT domain
        FROM scn_serves
        WHERE servername=? AND channel=?;''',(_servername,_channel))
      else:
        cur.execute('''SELECT domain
        FROM scn_serves
        WHERE servername=? AND channel=? AND pending=?;''',(_servername,_channel,_pending))
      
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    tempnew=[]
    for elem in temp:
      tempnew+=[elem[0],]
    return tempnew #domain

  
  def list_channels(self,_servername,_domain):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT channel
      FROM scn_serves
      WHERE servername=? AND domain=?;''',(_servername,_domain))
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #channelname

  def get_channel(self,_servername,_domain,_channelname):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT c.url,b.cert,a.secret, a.pending
      FROM scn_serves as a,scn_certs as b,scn_urls as c
      WHERE c.servername=? AND a.domain=? AND a.channel=?
      AND a.servername=c.servername AND b.name=c.certname;''',(_servername,_domain,_channelname))
      tempfetch=cur.fetchone()
    except Exception as u:
      printerror(u)
    con.close()
    return tempfetch #serverurl,cert,secret,pending state
  
  def del_channel(self,_servername,_domain,_channelname):
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
      AND domain=?
      AND channel=?''',(_servername,_domain,_channelname))
      con.commit()
    except Exception as u:
      printerror(u)
      return False
    con.close()
    return True
  
  def del_domain(self,_servername,_domain):
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
      AND domain=?''',(_servername,_domain))
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True
  
##TODO: cleanup cert db
  def del_server(self,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_urls
      WHERE servername=?''',(_servername,))
      cur.execute('''DELETE FROM scn_serves
      WHERE servername=?''',(_servername,))
      con.commit()
    except Exception as u:
      con.rollback()
      printerror(u)
      return False
    con.close()
    return True
  def get_cert(self,_certname):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT cert
      FROM scn_certs
      WHERE name=?''',(_certname,))
      tempfetch=cur.fetchone()
    except Exception as u:
      printerror(u)
        
    #strip tupel
    if tempfetch is not None:
      tempfetch=tempfetch[0]
    return tempfetch #cert or None
  def get_cert_name(self,_cert):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT name
      FROM scn_certs
      WHERE cert=?''',(_cert,))
      tempfetch=cur.fetchone()
    except Exception as u:
      printerror(u)
    con.close()
    #strip tupel
    if tempfetch is not None:
      tempfetch=tempfetch[0]
    return tempfetch #cert or None


  def get_server(self,_servername):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT a.url,b.cert,b.name
      FROM scn_urls as a, scn_certs as b
      WHERE a.servername=? AND a.certname=b.name''',(_servername,))
      tempfetch=cur.fetchone()
    except Exception as u:
      printerror(u)
    con.close()
    return tempfetch #serverurl,cert,name or None

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
      cur.execute('''SELECT servername FROM scn_urls WHERE url=?''',(_url,))
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp #serverurls

  def list_servers(self):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printdebug(u)
      return None
    try:
      cur = con.cursor()
      cur.execute('''SELECT servername,url,certname FROM scn_urls
      ORDER BY servername ASC''')
      temp=cur.fetchall()
    except Exception as u:
      printerror(u)
    con.close()
    return temp # [(servername),...]


  def list_serves(self,_channelname=None):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      printerror(u)
      return None
    temp=None
    try:
      #con.beginn()
      cur = con.cursor()
      if _channelname==None:
        cur.execute('''SELECT servername,domain,channel,pending
        FROM scn_serves
        ORDER BY servername,domain ASC''')
      else:
        cur.execute('''SELECT servername,domain,channel,pending
        FROM scn_serves
        WHERE channel=?
        ORDER BY servername,domain ASC''')

      temp=cur.fetchall()
    except Exception as u:
      printdebug(u)
      return None
    con.close()
    return temp






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
    #split ip address and port 
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
