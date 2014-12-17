#! /usr/bin/env python3


import threading
import signal
import sys
import time

from scn_client import client_master,scn_client,scn_server_client,scn_sock_client


from gi.repository import Gtk,Gdk

from scn_config import default_config_folder, scn_host


from gui.servernavtab import servernavtab

cm=client_master()


#normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE
icons=Gtk.IconTheme.get_default()


#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with domains on server (compressed)
#a subwindow with actions



class scnGUI(servernavtab):
  state_widget=None
  note_main=None
  linkback=None
  builder=None
  cur_server=None #use only after set by scnupdate
  cur_domain=None #use only after set by scnupdate
  cur_channel=None #use only after set by scnupdate
  box_select_handler_id=None
  box_activate_handler_id=None

  navbar=None
  navbox=None
  navcontent=None
  listelems=None
  statusbar=None
  messagecount=0
  messageid=1
  win=None
  clip=None
  _cache_request_channel=None
  _cache_request_hashes=None
  
  def __init__(self,_linkback,_uipath):
    self.linkback=_linkback
    self.builder=Gtk.Builder()
    self.builder.add_from_file(_uipath)
    self.clip=Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    #_uipath);
    #win=self.builder.get_object("mainwindow")
    #win.
    
    self.win=self.builder.get_object("mainwindow")
    self.navbar=self.builder.get_object("navbar")
    self.statusbar=self.builder.get_object("statusbar")

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

      
run=True

def signal_handler(*args):
  global run
  #win.close()
  run=False
  #app.close()

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

  scnGUI(cm,"guiscn.glade")
  while run==True:
    Gtk.main_iteration_do(True)
  
  sys.exit(0)
