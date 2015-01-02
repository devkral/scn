#! /usr/bin/env python3


import threading
import signal
import sys
import time
import logging

from scn_client import scn_client,scn_server_client,scn_sock_client
from scn_client import cm # client_master

from gi.repository import Gtk,Gdk,Gio

from scn_config import default_config_folder, scn_host


from gui.servernavtab import servernavtab


icons=Gtk.IconTheme.get_default()

#cm=client_master()


#normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE



#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with domains on server (compressed)
#a subwindow with actions



class scnApp(Gtk.Application,logging.NullHandler):
  linkback=None
  mainbuilder=None
  def __init__(self,_linkback):
    Gtk.Application.__init__(self,
                             application_id="org.scn.scn",
                             flags=Gio.ApplicationFlags.FLAGS_NONE)
    
    #logging.NullHandler.__init__(self)
    #logging.basicConfig(handlers=self)
    self.linkback=_linkback
    self.mainbuilder=Gtk.Builder.new_from_file("gui/guiscn.glade")
    self.connect("activate", self.createMainWin)
    
  def createMainWin(self,app):
    t=scnGUI(app.linkback,self.mainbuilder)
    app.add_window(t.win)
    
  def createFriendWin(self,app):
    pass



  
class scnGUI(servernavtab):
  
  linkback=None
  builder=None
  
  messagecount=0
  messageid=1
  
  statusbar=None
  win=None
  mainnote=None
  clip=None #clipboard


  def __init__(self,_linkback,_builder):
    #logging.NullHandler.__init__(self)
    #logging.basicConfig(handlers=self)
    self.linkback=_linkback
    self.builder=_builder
    self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    self.win=self.builder.get_object("mainwindow")
    self.navbar=self.builder.get_object("navbar")
    self.statusbar=self.builder.get_object("statusbar")
    self.mainnote=self.builder.get_object("mainnote")

    servernavtab.__init__(self)
    

    self.builder.connect_signals(self)
    
    self.update()
  
  

  def destroy_handler(self,*args):
    signal_handler()

  def pushint(self):
      time.sleep(5)
      #self.messagecount-=1
      self.statusbar.pop(self.messageid)

  def pushmanage(self,*args):
    #self.messagecount+=1
    #if self.messagecount>1:
    t=threading.Thread(target=self.pushint)
    t.daemon = True
    t.start()

  def handle(self,record):
    self.statusbar.push(self.messageid,record)
    
    
run=True

def signal_handler(*args):
  global run
  #win.close()
  run=False
  #app.close()

if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  cm.main=scn_client(cm,default_config_folder)

  handler=scn_server_client
  handler.linkback=cm
  cm.receiver = scn_sock_client((scn_host, 0),handler, cm)
  #port 0 selects random port
  signal.signal(signal.SIGINT, signal_handler)
  client_thread = threading.Thread(target=cm.receiver.serve_forever)
  client_thread.daemon = True
  client_thread.start()

  cm.gui=scnApp(cm)
  cm.gui.register()
  cm.gui.activate()
  while run==True:
    Gtk.main_iteration_do(True)
  
  sys.exit(0)
