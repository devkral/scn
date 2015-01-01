
import sqlite3
import logging


#scn_servs: _channelname: _server,_domain:secret
class scn_friends_sql(object):
  view_cur = None
  db_path = None
  logger = None
  db_connect = None

  
  def __init__(self,_db):
    self.db_path=_db
    #self.db_connect=db_connect(self)
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      logging.error(e)
      return
    try:
      # pservername TEXT, pdomain TEXT: primary server,domain; for updates
      con.execute('''CREATE TABLE if not exists
      scn_friends(friendname TEXT, pservername TEXT, pdomain TEXT, PRIMARY KEY(friendname))''')

      con.execute('''CREATE TABLE if not exists
      scn_friends_cert(friendname TEXT,clientname TEXT, cert BLOB, PRIMARY KEY(clientname)
      FOREIGN KEY(friendname) REFERENCES scn_friends(friendname) ON UPDATE CASCADE ON DELETE CASCADE,
      PRIMARY KEY(friendname,clientname))''')
      
      con.execute('''CREATE TABLE if not exists
      scn_friends_server(friendname TEXT, servername TEXT, domain TEXT,
      FOREIGN KEY(friendname) REFERENCES scn_friends(friendname) ON UPDATE CASCADE ON DELETE CASCADE,
      PRIMARY KEY(friendname,servername))''')
      con.commit()
    except Exception as u:
      con.rollback()
      logging.error(u)
    con.close()

  def get_friend_cert(self,_friendname):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as e:
      logging.error(e)
      return None
    try:
      cur = con.cursor()
      cur.execute('''SELECT clientname,cert
      FROM scn_friends_cert
      WHERE friendname=?''',(_friendname,))
      temp=cur.fetchall()
    except Exception as u:
      logging.error(u)
    con.close()
    return temp #return clientname,cert list

  #if servername=None return all
  def get_server(self,_friendname,_servername=None):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
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
      logging.error(u)
    con.close()
    return temp #return servernamelist

  def add_server(self,_friendname,_servername,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT into scn_friends_server(friendname,servername,domain) values(?,?,?);''',(_friendname,_servername,_domain))
      
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True
  
  # update an existing server
  def update_server(self,_servername_old,_servername_new,_friendname=None):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      if _friendname is None:
        cur.execute('''UPDATE scn_friends_server SET servername=? WHERE servername=?;''',(_servername_new,_servername_old))
      else:
        cur.execute('''UPDATE scn_friends_server SET servername=? WHERE servername=? AND friendname=?;''',(_servername_new,_servername_old,_friendname))
        
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  def update_friend_cert(self,_friendname,_client,_cert=None):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    if self.get_friend(_friendname) is None and _cert is None:
      logging.error("Error: Certificate must be specified")
      return False
    try:
      cur = con.cursor()
      if _cert is not None:
        cur.execute('''INSERT OR REPLACE into scn_friends_server(friendname,cert) values(?,?);''',(_friendname,_cert))
      else:
        cur.execute('''INSERT OR REPLACE into scn_friends(friendname) values(?);''',(_friendname,))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  def del_friend(self,_friendname):
    if self.get_friend(_friendname) is None:
      logging.error("Deletion of non-existent object")
      return True
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends
      WHERE friendname=?;''',(_friendname,))
      cur.execute('''DELETE FROM scn_friends_cert
      WHERE friendname=?;''',(_friendname,))
      cur.execute('''DELETE FROM scn_friends_server
      WHERE friendname=?;''',(_friendname,))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  def del_friend_cert(self,_friendname,_clientname):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends_cert
      WHERE friendname=? AND clientname=?;''',(_friendname,_clientname))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  
  def del_server_friend(self,_friendname,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends_server
      WHERE friendname=? AND servername=?;''',(_friendname,_servername))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True
  

  #delete server from all friends
  def del_server_all(self,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      cur = con.cursor()
      cur.execute('''DELETE FROM scn_friends_server
      WHERE servername=?;''',(_servername,))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
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
      logging.error(u)
      return
    try:
      con.execute('''CREATE TABLE if not exists
      scn_serves(servername TEXT, domain TEXT, channel TEXT,
      secret BLOB, type TEXT, pending BOOLEAN, active BOOLEAN,PRIMARY KEY(servername,domain,channel),
      FOREIGN KEY(servername) REFERENCES scn_urls(servername) ON UPDATE CASCADE ON DELETE CASCADE);''')


      con.execute('''CREATE TABLE if not exists scn_urls(servername TEXT, url TEXT, certname TEXT,
      PRIMARY KEY(servername,url,certname),
      FOREIGN KEY(certname) REFERENCES scn_certs(certname) ON UPDATE CASCADE ON DELETE CASCADE  );''')
      
      con.execute('''CREATE TABLE if not exists scn_certs(name TEXT, cert BLOB,PRIMARY KEY(name), UNIQUE(cert)  );''')

      con.commit()
    except Exception as u:
      con.rollback()
      logging.error(u)
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
      logging.error(u)
      return False
    try:
      cur = con.cursor()
      if tcertname is None:
        cur.execute('''INSERT into scn_certs(name,cert) values (?,?);''',(_certname,_cert))
      cur.execute('''INSERT into scn_urls(servername,url,certname) values(?,?,?);''',(_servername,_url,_certname))
      
      con.commit()
    except sqlite3.IntegrityError:
      logging.debug("exists already")
      con.rollback()
      return False
    except Exception as u:
      logging.error(u)
      con.rollback()
      return False
    con.close()
    return True

  def update_server(self,_servername,_url,_cert):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
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
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_urls SET servername=? WHERE servername=?;''',(_servername_new,_servername))
      con.commit();
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_certs SET name=? WHERE name=?;''',(_certname_new,_certname))
      cur.execute('''UPDATE scn_urls SET certname=? WHERE certname=?;''',(_certname_new,_certname)) #why does the constraint not work?
      con.commit();
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_urls SET certname=? WHERE servername=?;''',(_certname_new,_servername))
      con.commit();
    except Exception as u:
      logging.error(u)
      con.rollback()
      return False
    con.close()
    return True

  def add_serve(self,_servername,_domain,
                _channel,_secret,_type):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''INSERT into scn_serves(
      servername,
      domain,
      channel,
      secret,
      type,
      pending,active)
      values (?,?,?,?,?,1,1)''',(_servername,_domain,_channel,_secret,_type))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  def update_serve_secret(self,_servername,_domain,_channel,_secret):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    con.close()
    return True
    
  def update_serve_type(self,_servername,_domain,_channel,_type):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_serves SET type=?
      WHERE
      servername=? AND
      domain=? AND
      channel=?;''',(_type,_servername,_domain,_channel))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True
  
  def update_serve_pendingstate(self,_servername,_domain,_channel,_pendingstate=False):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    con.close()
    return True
  
  def pause_serve(self,_servername,_domain,_channel,_active=False):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return False
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''UPDATE scn_serves SET active=? WHERE
      servername=? AND domain=? AND channel=?;
      ''',(_active,_servername,_domain,_channel))
      con.commit();
    except Exception as u:
      con.rollback()
      logging.error(u)
      return False
    con.close()
    return True

  def list_domains(self,_servername,_channel=None,_pending=None):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
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
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT channel
      FROM scn_serves
      WHERE servername=? AND domain=?;''',(_servername,_domain))
      temp=cur.fetchall()
    except Exception as u:
      logging.error(u)
    con.close()
    return temp #channelname

  def get_channel(self,_servername,_domain,_channelname):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT c.url,b.cert,a.secret, a.type, a.pending, a.active
      FROM scn_serves as a,scn_certs as b,scn_urls as c
      WHERE c.servername=? AND a.domain=? AND a.channel=?
      AND a.servername=c.servername AND b.name=c.certname;''',(_servername,_domain,_channelname))
      tempfetch=cur.fetchone()
    except Exception as u:
      logging.error(u)
    con.close()
    return tempfetch #serverurl,cert,secret,type,pending state,active
  
  def del_channel(self,_servername,_domain,_channelname):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    con.close()
    return True
  
  def del_domain(self,_servername,_domain):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    con.close()
    return True
  
##TODO: cleanup cert db
  def del_server(self,_servername):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return False
    con.close()
    return True
  def get_cert(self,_certname):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT cert
      FROM scn_certs
      WHERE name=?''',(_certname,))
      tempfetch=cur.fetchone()
    except Exception as u:
      logging.error(u)
        
    #strip tupel
    if tempfetch is not None:
      tempfetch=tempfetch[0]
    return tempfetch #cert or None
  def get_cert_name(self,_cert):
    tempfetch=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT name
      FROM scn_certs
      WHERE cert=?''',(_cert,))
      tempfetch=cur.fetchone()
    except Exception as u:
      logging.error(u)
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
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT a.url,b.cert,b.name
      FROM scn_urls as a, scn_certs as b
      WHERE a.servername=? AND a.certname=b.name''',(_servername,))
      tempfetch=cur.fetchone()
    except Exception as u:
      logging.error(u)
    con.close()
    return tempfetch #serverurl,cert,name or None

  def get_by_url(self,_url):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT servername FROM scn_urls WHERE url=?''',(_url,))
      temp=cur.fetchall()
    except Exception as u:
      logging.error(u)
    con.close()
    return temp #serverurls

  def list_servers(self):
    temp=None
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    try:
      cur = con.cursor()
      cur.execute('''SELECT servername,url,certname FROM scn_urls
      ORDER BY servername ASC''')
      temp=cur.fetchall()
    except Exception as u:
      logging.error(u)
    con.close()
    return temp # [(servername),...]


  def list_serves(self):
    try:
      con=sqlite3.connect(self.db_path)
    except Exception as u:
      logging.error(u)
      return None
    temp=None
    try:
      #con.beginn()
      cur = con.cursor()
      cur.execute('''SELECT servername,domain,channel,type,pending,active
      FROM scn_serves AND active=1
      ORDER BY servername,domain,channel ASC''')
      
      temp=cur.fetchall()
    except Exception as u:
      logging.error(u)
      return None
    con.close()
    return temp
