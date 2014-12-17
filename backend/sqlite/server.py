

import hashlib
import tempfile
import sqlite3

from scn_config import max_channel_nodes

class scn_ip_store(object):
  db_pers = None
  db_tmp = None
  db_temp_keep_alive = None
  logger = None
  def __init__(self,dbpers,_logger):
    self.db_pers=dbpers
    self.db_temp_keep_alive=tempfile.NamedTemporaryFile()
    self.db_tmp=self.db_temp_keep_alive.name
    self.logger = _logger
    try:
      con=sqlite3.connect(self.db_pers)
      con.execute('''CREATE TABLE if not exists addr_store(domain TEXT, channel TEXT, clientid INT, addr_type TEXT, addr TEXT, hashed_pub_cert TEXT, PRIMARY KEY(domain,channel,hashed_pub_cert));''')
      con.commit()
      con.close()
    except Exception as e:
      self.logger.error(e)
      con.close()
      return

    try:
      con=sqlite3.connect(self.db_tmp)
      con.execute('''CREATE TABLE if not exists addr_store(domain TEXT, channel TEXT, clientid INT, addr_type TEXT, addr TEXT,hashed_pub_cert TEXT, PRIMARY KEY(domain,channel,hashed_pub_cert));''')
      
      con.commit()
      con.close()
    except Exception as e:
      self.logger.error(e)
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
      con.close()
      self.logger.error(e)
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
      self.logger.error(e)
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
      self.logger.error(e)
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
      self.logger.error(e)
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
      self.logger.error(e)
      return False
    con.close()
    con=sqlite3.connect(self.db_tmp)
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM addr_store
      WHERE domain=?;''',(_domain,))
    except Exception as e:
      con.close()
      self.logger.error(e)
      return False
    con.close()
    return True


class scn_domain_sql(object):
#  message=""
#  pub_cert=None
#  scn_channels={"admin":[]}
  dbcon=None
  domain=None
  logger=None

  def __init__(self,dbcon,_domain,_logger):
    self.dbcon=dbcon
    self.domain=_domain
    self.logger=_logger

  def __del__(self):
    self.dbcon.close()
  def set_message(self,_message):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''UPDATE scn_domain SET message=? WHERE name=?''', (_message,self.domain))
      self.dbcon.commit()
    except Exception as e:
      self.dbcon.rollback()
      self.logger.error(e)
      return False
    return True
  def get_message(self):
    message=None
    try:
      cur = self.dbcon.cursor()
      cur.execute('''SELECT message FROM scn_domain WHERE name=?''',(self.domain,))
      message=cur.fetchone()
    except Exception as e:
      self.logger.error(e)
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
      self.logger.error(e)
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
      self.logger.error(e)
    return ob #channelname
  
  
  def length(self, _channel):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(''' SELECT nodeid
      FROM scn_node WHERE scn_domain=? AND channelname=? ''', (self.domain,_channel))
      length=len(cur.fetchall())
    except Exception as e:
      self.logger.error(e)
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
      self.logger.error(e)
    #strip tupel
    if ob is not None:
      ob=ob[0]
    return ob #hashed_pub_cert


  # name,secret,cert
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
          scn_node(scn_domain,channelname, nodeid, nodename, hashed_secret, hashed_pub_cert)
          values(?,?,?,?,?,?);''',
          (self.domain,_channelname,c,_secrethashlist[c][0],_secrethashlist[c][1],_secrethashlist[c][2]))
        elif c<b:
          cur.execute('''DELETE FROM scn_node WHERE scn_domain=? AND channelname=? AND nodeid=?;''',(self.domain,_channelname,c))
      self.dbcon.commit()
    except Exception as e:
      self.dbcon.rollback()
      self.logger.error(e)
      return False
    return True

  def delete_channel(self,_channelname):
    try:
      cur = self.dbcon.cursor()
      cur.execute('''DELETE FROM scn_node WHERE scn_domain=? AND channelname=?;''',(self.domain,_channelname))
      self.dbcon.commit()
    except Exception as e:
      self.logger.error(e)
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
      cur.execute('''SELECT hashed_secret,hashed_pub_cert FROM scn_node WHERE scn_domain=? AND channelname=?;''',(self.domain,_channelname))
    except Exception as e:
      self.logger.error(e)
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
      self.logger.error(e)
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
      self.logger.error(e)
      return False
    return True

class scn_domain_list_sqlite(object):
  db_path=None
  def __init__(self, db):
    self.db_path=db
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return
    try:
      con.execute('''CREATE TABLE if not exists scn_domain(name TEXT, message TEXT);''')
      con.commit()

      con.execute('''CREATE TABLE if not exists scn_node(scn_domain TEXT,channelname TEXT, nodeid INTEGER, nodename TEXT, hashed_pub_cert TEXT, hashed_secret TEXT, PRIMARY KEY(scn_domain,channelname,nodeid),FOREIGN KEY(scn_domain) REFERENCES scn_domain(name) ON UPDATE CASCADE ON DELETE CASCADE);''')
      con.commit()
    except Exception as e:
      con.rollback()
      self.logger.error(e)
    con.close()

  def get(self,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('SELECT name FROM scn_domain WHERE name=?', (_domain,))
      resultname=cur.fetchone()
      if resultname is not None:
        ob=scn_domain_sql(con,resultname[0]) 
    except Exception as e:
      self.logger.error(e)
    return ob
  
  def list_domains(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return None
    ob=None
    try:
      cur = con.cursor()
      cur.execute('''
      SELECT name FROM scn_domain
      ORDER BY name ASC''')
      ob=cur.fetchall()
    except Exception as e:
      self.logger.error(e)
    return ob

  def length(self, _domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return 0
    length=0
    try:
      cur = con.cursor()
      cur.execute(''' SELECT DISTINCT channelname
      FROM scn_node WHERE scn_domain=?''', (_domain,))
      length=cur.rowcount
    except Exception as e:
      self.logger.error(e)
      length=0
    return length

  def del_domain(self,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
      return False
    if self.get(_domain) is None:
      self.logger.debug("Deletion of non-existent domain")
      return True
    state=True
    try:
      cur = con.cursor()
      #shouldn't throw error if not available
      cur.execute('''DELETE FROM scn_domain WHERE name=?;''',(_domain,))
      con.commit()
    except Exception as e:
      con.rollback()
      self.logger.error(e)
      state=False
    con.close()
    return state

  # secret,cert
  def create_domain(self,_domain,_secrethash,_certhash):
    if self.get(_domain) is not None:
      return None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      self.logger.error(e)
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
      self.logger.error(e)
    return self.get(_domain)
