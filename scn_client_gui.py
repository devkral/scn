#! /usr/bin/env python3


import threading
import signal
import sys
import time

from scn_client import client_master,scn_client,scn_server_client,scn_sock_client
from scn_base import check_invalid_s,printerror

from gi.repository import Gtk,Gdk

from scn_config import default_config_folder, scn_host

cm=client_master()


#normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE
icons=Gtk.IconTheme.get_default()


#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with domains on server (compressed)
#a subwindow with actions

class scnDeletionDialog(Gtk.Dialog):
  def __init__(self, _parent, _server,_domain=None,_channel=None):
    Gtk.Dialog.__init__(self, "Confirm Deletion", _parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    if _domain is not None and _channel is not None:
      label=Gtk.Label("Shall channel \""+_channel+"\" of "+_server+"/"+_domain+" be deleted?")
    elif _domain is not None and _channel is None:
      label=Gtk.Label("Shall domain \""+_domain+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()

class scnServerAddDialog(Gtk.Dialog):
  servername=None
  certname=None
  certchange=None
  url=None
  def __init__(self, _parent, _title):
    self.parent=_parent
    self.servername=Gtk.Entry()
    self.servername.set_hexpand(True)
    self.servername.set_text("")
    self.certname=Gtk.Entry()
    self.certname.set_hexpand(True)
    self.certname.set_placeholder_text("(optional)")
    self.url=Gtk.Entry()
    self.url.set_hexpand(True)
    
    Gtk.Dialog.__init__(self, _title, self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    box = self.get_content_area()
    cont=Gtk.Grid()
    box.add(cont)

    tsname=Gtk.Label("Servername: ")
    tsname.set_halign(Gtk.Align.END)
    cont.attach(tsname,0,0,1,1)
    cont.attach(self.servername,1,0,1,1)
    tcn=Gtk.Label("Name Server Cert extra: ")
    tcn.set_halign(Gtk.Align.END)
    cont.attach(tcn,0,1,1,1)
    cont.attach(self.certname,1,1,1,1)
    turl=Gtk.Label("Url: ")
    turl.set_halign(Gtk.Align.END)
    cont.attach(turl,0,2,1,1)
    cont.attach(self.url,1,2,1,1)

    self.show_all()

    
class scnServerEditDialog(Gtk.Dialog):
  servername=None
  certname=None
  certchange=None
  url=None
  def __init__(self, _parent, _title, _servername,_serverinfo):
    self.parent=_parent
    self.servername=Gtk.Entry()
    self.servername.set_hexpand(True)
    self.servername.set_text(_servername)
    self.certname=Gtk.Entry()
    self.certname.set_hexpand(True)
    self.certname.set_text(_serverinfo[2])
    self.certchange=Gtk.CheckButton(label="Change to cert")
    self.url=Gtk.Entry()
    self.url.set_hexpand(True)
    self.url.set_text(_serverinfo[0])
    
    Gtk.Dialog.__init__(self, _title, self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    box = self.get_content_area()
    cont=Gtk.Grid()
    box.add(cont)

    tsname=Gtk.Label("Servername: ")
    tsname.set_halign(Gtk.Align.END)
    cont.attach(tsname,0,0,1,1)
    cont.attach(self.servername,1,0,1,1)
    tcn=Gtk.Label("Certificate name: ")
    tcn.set_halign(Gtk.Align.END)
    cont.attach(tcn,0,1,1,1)
    cont.attach(self.certname,1,1,1,1)
    cont.attach(self.certchange,2,1,1,1)
    turl=Gtk.Label("Url: ")
    turl.set_halign(Gtk.Align.END)
    cont.attach(turl,0,2,1,1)
    cont.attach(self.url,1,2,1,1)

    self.show_all()

class scnNameAddDialog(Gtk.Dialog):
  name=None
  def __init__(self, _parent, _title,_servername,_parentname=None):
    self.parent=_parent
    self.name=Gtk.Entry()
    self.name.set_hexpand(True)
#    self.name.set_text(_name)
    
    Gtk.Dialog.__init__(self, _title, self.parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    box = self.get_content_area()
    cont=Gtk.Grid()
    box.add(cont)
    lname=Gtk.Label()
    if _parentname==None:
      lname.set_text("On "+_servername+" add:")
    else:
      lname.set_text("On "+_servername+": add to "+_parentname+":")
    lname.set_halign(Gtk.Align.START)
    cont.attach(lname,0,0,2,1)
    
    tname=Gtk.Label("Name: ")
    tname.set_halign(Gtk.Align.END)
    cont.attach(tname,0,1,1,1)
    cont.attach(self.name,1,1,1,1)

    self.show_all()




class scnGUI(object):
  confirm_button_id=None
  reset_button_id=None
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
  
  def __init__(self,_linkback,_uipath):
    self.linkback=_linkback
    self.builder=Gtk.Builder()
    self.builder.add_from_file(_uipath)
    #_uipath);
    #win=self.builder.get_object("mainwindow")
    #win.
    
    self.win=self.builder.get_object("mainwindow")
    self.navbar=self.builder.get_object("navbar")
    self.statusbar=self.builder.get_object("statusbar")

    self.navcontent=self.builder.get_object("navcontent")
    self.navbox=self.builder.get_object("navbox")
    renderer = Gtk.CellRendererText()
    renderer2 = Gtk.CellRendererText()
    tempelem = Gtk.TreeViewColumn("", renderer2, text=0)
    self.listelems = Gtk.TreeViewColumn("Title", renderer, text=1)
    self.navbox.append_column(tempelem)
    self.navbox.append_column(self.listelems)
    
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
      
  def update(self,_server=None,_domain=None,_channel=None):
    if _server=="":
      _server=None
    self.cur_server=_server
    self.cur_domain=_domain
    self.cur_channel=_channel

      #self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    if _channel is not None:
      self.navbar.set_text(self.cur_server+"/"+self.cur_domain+"/"+self.cur_channel)
      self.buildchannelgui()

    elif _domain is not None:
      self.navbar.set_text(self.cur_server+"/"+self.cur_domain+"/")
      self.builddomaingui()

    elif _server is not None:
      self.navbar.set_text(self.cur_server+"/")
      self.buildservergui()
      
    else:
      self.navbar.set_text("")
      self.buildNonegui()
  #update by navbar
  def navbarupdate(self, *args):
    splitnavbar=self.navbar.get_text().strip("/").rstrip("/").split("/")
    self.update(*splitnavbar[:3])

  def updateserverlist(self, *args):
    temp2=self.linkback.main.scn_servers.list_servers()
    if temp2 is None:
      return False
    self.listelems.set_title("Server")
    self.navbox.show()
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append(("",elem[0]))

  def updatedomainlist(self, *args):
    temp_remote=self.linkback.main.c_list_domains(self.cur_server)
    if temp_remote is None:
      return False
    temp_local=self.linkback.main.scn_servers.list_domains(self.cur_server)
    self.navbox.show()
    self.listelems.set_title("Domain")
    self.navcontent.clear()

    for elem in temp_local:
      if elem[0] not in temp_remote:
        self.navcontent.append(("local:",elem[0]))
    for elem in temp_remote:
      self.navcontent.append(("",elem))
    return True

  def updatechannellist(self, *args):
    temp2=self.linkback.main.c_list_channels(self.cur_server,self.cur_domain)
    if temp2 is None:
      return False
    self.navbox.show()
    self.listelems.set_title("Channel")
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append(("",elem))
      
  def updatenodelist(self, *args):
    self.navbox.show()
    self.navcontent.clear()
    temp2=self.linkback.main.c_get_channel_nodes(self.cur_server,self.cur_domain,self.cur_channel)
    if temp2 is None:
      return False
    self.listelems.set_title("Users")
    count=0;
    for elem in temp2:
      self.navcontent.append((str(count),elem[0]))
      count+=1
    return True

  def buildNonegui(self):
    if self.updateserverlist()==False:
      self.statusbar.push(self.messageid,"Error loading servers")
    
    self.builder.get_object("levelshowl").set_text("")

    #reconnect signals
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_server)
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_server)
    
    newob=self.builder.get_object("nocontext")
    cdin=self.builder.get_object("contextdropin")
    if len(cdin.get_children())==1:
      cdin.remove(cdin.get_children()[0])
    cdin.add(newob)

  def buildservergui(self):
    if self.updatedomainlist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return

    self.builder.get_object("levelshowl").set_text("Server Level")

    #reconnect signals
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_domain)
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_domain)
    
    newob=self.builder.get_object("servercontext")
    cdin=self.builder.get_object("contextdropin")
    if len(cdin.get_children())==1:
      cdin.remove(cdin.get_children()[0])
    cdin.add(newob)
    servermessagebuffer=self.builder.get_object("servermessage")
    servermessage=self.builder.get_object("servermessagev2")
    tempmes=self.linkback.main.c_get_server_message(self.cur_server)
    servermessage.set_editable(False)
    if tempmes is None:
      servermessagebuffer.set_text("")
    else:
      servermessagebuffer.set_text(tempmes)
      
    #hide controls if client is not server admin      
    if self.linkback.main.scn_servers.get_channel(self.cur_server,"admin","admin") is None:
      self.builder.get_object("servermessagecontrols").hide()
    else:
      servermessage.set_editable(True)
      self.builder.get_object("servermessagecontrols").show()
    

  def builddomaingui(self):
    if self.updatechannellist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildservergui()
      return

    if self.cur_domain=="admin":
      self.builder.get_object("levelshowl").set_text("Server Service Level")
    else:
      self.builder.get_object("levelshowl").set_text("Domain Level")
    
    #reconnect signals
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_channel)
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_channel)
    
    
    newob=self.builder.get_object("domaincontext")
    cdin=self.builder.get_object("contextdropin")
    if len(cdin.get_children())==1:
      cdin.remove(cdin.get_children()[0])
    cdin.add(newob)


    domainmessagel=self.builder.get_object("domainmessagel")    
    if self.cur_domain=="admin":
      domainmessagel.set_text("Servermessage")
    else:
      domainmessagel.set_text("Domainmessage")

    domainmessagebuffer=self.builder.get_object("domainmessage")
    domainmessage=self.builder.get_object("domainmessagev2")
    domainmessage.set_editable(False)       
    tempmes=self.linkback.main.c_get_domain_message(self.cur_server,self.cur_domain)
    if tempmes is None:
      domainmessagebuffer.set_text("")
    else:
      domainmessagebuffer.set_text(tempmes)
    
    #hide controls if client has no admin rights
    if self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin") is not None:
      domainmessage.set_editable(True)
      self.builder.get_object("domainmessagecontrols").show()
      self.builder.get_object("addchannelb").show()
      self.builder.get_object("delchannelb").show()
      self.builder.get_object("pinchannelorderb").show()
    else:
      self.builder.get_object("domainmessagecontrols").hide()
      self.builder.get_object("addchannelb").hide()
      self.builder.get_object("delchannelb").hide()
      self.builder.get_object("pinchannelorderb").hide()
      
  #channel
  def buildchannelgui(self):
    if self.cur_server is None or self.cur_domain is None or self.cur_channel is None:
      self.builddomaingui()
      return
    self.builder.get_object("levelshowl").set_text("Channel Level")
    
    self.updatenodelist()
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))

    #disconnect signals and set handler_id to 0
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.fill_node_data)
    
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None

    
    newob=self.builder.get_object("channelcontext")
    cdin=self.builder.get_object("contextdropin")
    if len(cdin.get_children())==1:
      cdin.remove(cdin.get_children()[0])
    cdin.add(newob)

    #hide renew secret if no secret is available
    if self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,self.cur_channel) is not None:
      self.builder.get_object("renewsecret").show()
    else:
      self.builder.get_object("renewsecret").hide()
      
    #hide admin options for non-admins
    if self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin") is None:
      self.builder.get_object("addnodeb1").hide()
      self.builder.get_object("delnodeb1").hide()
    else:
      self.builder.get_object("addnodeb1").show()
      self.builder.get_object("delnodeb1").show()
    
    channelfold=self.builder.get_object("dropinchannelcontext1")
    if len(channelfold.get_children())>=1:
      channelfold.remove(channelfold.get_children()[0])
    channelf=self.builder.get_object("dropinchannelcontext2")
    if len(channelf.get_children())>=1:
      channelf.remove(channelf.get_children()[0])
    channelf.add(self.genchannelcontext(self.cur_channel))
    
    #self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_channel)
    #self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_channel)  

  def genchannelcontext(self,_channel):
    if _channel=="admin":
      self.builder.get_object("channel1").set_text("Admin")
      self.builder.get_object("channel2").set_text("Admin")
      if self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin") is None:
        noperm=self.builder.get_object("nopermissionchannel")
        self.fill_request(self.builder.get_object("genrequestdropin1"),_channel)
        return noperm
      tcha=self.builder.get_object("adminchannel")
      return tcha
    elif _channel=="special":# or         _channel in self.linkback.main.special_channels
      self.builder.get_object("channel1").set_text("Special")
      self.builder.get_object("channel2").set_text("Special")
      if self.scn_servers.get_channel(self.cur_server,self.cur_domain,_channel) is None and \
         self.scn_servers.get_channel(self.cur_server,self.cur_domain,"special") is None and \
         self.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin") is None:
        noperm=self.builder.get_object("nopermissionchannel")
        #self.fill_request(self.builder.get_object("genrequestdropin1"))
        return noperm
      tcha=self.builder.get_object("specialchannel")
      return tcha
    elif _channel=="main":
      self.builder.get_object("channel1").set_text("Main")
      self.builder.get_object("channel2").set_text("Main")
      tcha=self.builder.get_object("genericchannel")
      return tcha
    elif _channel=="notify":
      self.builder.get_object("channel1").set_text("Notify")
      self.builder.get_object("channel2").set_text("Notify")
      tcha=self.builder.get_object("genericchannel")
      return tcha
    else:
      self.builder.get_object("channel1").set_text("__"+_channel)
      self.builder.get_object("channel2").set_text("__"+_channel)
      tcha=self.builder.get_object("genericchannel")
      return tcha

  ### fill section
  def fill_request(self,_ob,_channel):
    if len(_ob.get_children())==1:
      _ob.get_children()[0].destroy()
    _ob.add(Gtk.Label("Not implemented"))


  def fill_node_data(self,*args):
    tempnodeid=self.navbox.get_selection().get_selected()
    if tempnodeid[1] is None:
      return
    else:
      try:
        tempnodeid=int(tempnodeid[0][tempnodeid[1]][1])
      except Exception:
        return
    
    tempnodel=self.linkback.main.c_get_channel_addr(self.cur_server,self.cur_domain,self.cur_channel,tempnodeid)
    addrtype=self.builder.get_object("addrtypelabel")
    addr=self.builder.get_object("addrlabel")
    nodehash=self.builder.get_object("nodecerthashlabel")
    print(tempnodel)
    if tempnodel is None:
      addrtype.set_text("N/A")
      addr.set_text("N/A")
      nodehash.set_text("N/A")
    else:
      addrtype.set_text(tempnodel[0][0])
      addr.set_text(tempnodel[0][1])
      nodehash.set_text(tempnodel[0][1])
    
  ### select section  ###
  def goback_none(self,*args):
    self.update()

  def select_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(temp[0][temp[1]][1])

  def goback_server(self,*args):
    self.update(self.cur_server)

  def select_domain(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.cur_server is None:
      return  
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,temp[0][temp[1]][1])

  def goback_domain(self,*args):
    self.update(self.cur_server,self.cur_domain) 
  
  def select_channel(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.cur_server is None:
      return
    if self.cur_domain is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,self.cur_domain,temp[0][temp[1]][1])
    
  ### message section ###

  def select_context_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    try:
      tempmessage=self.linkback.main.c_get_server_message(temp[0][temp[1]][1])
    except Exception:
      return
    guimessage=self.builder.get_object("servermessagev1")
    messagebuffer=self.builder.get_object("servermessage")
    guimessage.set_editable(False)
    if tempmessage is None:
      messagebuffer.set_text("")
    else:
      messagebuffer.set_text(tempmessage)

  def select_context_domain(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    tdomain=temp[0][temp[1]][1]
    
    messageframe=self.builder.get_object("domainmessagef")
    messagebuffer=self.builder.get_object("domainmessage")
    domainmessageview=self.builder.get_object("domainmessagev2")
    domainmessageview.set_editable(False)
    
    if tdomain=="admin":
      messageframe.hide()
    else:
      messageframe.show()
      try:
        tempmessage=self.linkback.main.c_get_domain_message(self.cur_server,tdomain)
      except Exception:
        return
      if tempmessage is None:
        messagebuffer.set_text("")
      else:
        messagebuffer.set_text(tempmessage)

  def select_context_channel(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    channelfold=self.builder.get_object("dropinchannelcontext2")
    if len(channelfold.get_children())>=1:
      channelfold.remove(channelfold.get_children()[0])
    channelf=self.builder.get_object("dropinchannelcontext1")
    if len(channelf.get_children())>=1:
      channelf.remove(channelf.get_children()[0])
    channelf.add(self.genchannelcontext(temp[0][temp[1]][1]))
    channelf.show_all()
  ### server section ###

  def delete_server_intern(self,_delete_server):
    returnstate=False
    dialog = scnDeletionDialog(self.win,_delete_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_server(_delete_server)==True:
          self.updateserverlist()
          returnstate=True
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error, something happened")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    return returnstate

  #get server by navbox
  def delete_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.delete_server_intern(temp[0][temp[1]][1])

  #get server by current selection
  def delete_server2(self,*args):
    if self.cur_server is None:
      return
    if self.delete_server_intern(self.cur_server)==True:
      self.update()


  def add_server(self,*args):
    dialog = scnServerAddDialog(self.win,"Add new server")
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        tempcertname=dialog.certname.get_text()
        if tempcertname=="":
          tempcertname=None
        if self.linkback.main.c_add_server(dialog.servername.get_text(),dialog.url.get_text(),tempcertname)==True:
          self.updateserverlist()
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error2")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    
  def edit_server2(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.edit_server_intern(temp[0][temp[1]][1])==True:
      self.updateserverlist()

  def edit_server(self,*args):
    if self.edit_server_intern(self.cur_server)==True:
      self.update()

  def edit_server_intern(self,_server):
    returnstate=False
    temp=self.linkback.main.scn_servers.get_server(_server)
    if temp is None:
      self.statusbar.push(self.messageid,"\""+_server +"\" does not exist")
      return
    #todo: show cert
    dialog = scnServerEditDialog(self.win,"Edit server",_server,temp)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        tempcertname=dialog.certname.get_text()
        if check_invalid_s(tempcertname)==False or check_invalid_s(dialog.servername.get_text())==False:
          printerror("Invalid characters")
          dialog.destroy()
          return False
        if tempcertname!="" and tempcertname!=temp[2]:
          if dialog.certchange.get_active()==False:
            if self.linkback.main.scn_servers.update_cert_name(temp[2],tempcertname)==False:
              dialog.destroy()
              self.statusbar.push(self.messageid,"Certificate renaming failed")
              return False
          else:
            if self.linkback.main.scn_servers.change_cert(_server,tempcertname)==False:
              self.statusbar.push(self.messageid,"Changing certificate failed")
              dialog.destroy()
              return False
        if dialog.servername!=_server:
          self.linkback.main.scn_servers.update_server_name(_server,dialog.servername.get_text())
          
        if self.linkback.main.c_update_server(dialog.servername.get_text(),dialog.url.get_text())==True:
          returnstate=True
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
      else:
        self.statusbar.push(self.messageid,"Aborted")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    return returnstate

  def register_domain(self,*args):
    dialog = scnNameAddDialog(self.win,"Register",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_register_domain(self.cur_server,dialog.name.get_text())==True:
          self.updatedomainlist()
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error")
      else:
        self.statusbar.push(self.messageid,"Aborted")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()


  def delete_domain_intern(self,_delete_domain):
    returnstate=False
    if _delete_domain=="admin":
      self.statusbar.push(self.messageid,"Can't delete admin")
      return
    dialog = scnDeletionDialog(self.win,self.cur_server,_delete_domain)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_domain(self.cur_server,_delete_domain)==True:
          self.linkback.main.scn_servers.del_domain(self.cur_server,_delete_domain)
          self.statusbar.push(self.messageid,"Success")
          returnstate=True
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error, something happened")
        
          
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    if returnstate==False:
      pass
      #delete anyway dialog
      #self.linkback.main.scn_servers.del_domain(self.cur_server,_delete_domain)

    return returnstate

  def delete_domain(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.delete_domain_intern(temp[0][temp[1]][1])==True:
      self.updatedomainlist()


  def delete_domain2(self, *args):
    if self.delete_domain_intern(self.cur_domain)==True:
      self.update(self.cur_server)
      self.updatedomainlist()
  ### domain/channel section ###

  def add_channel(self,*args):
    dialog = scnNameAddDialog(self.win,"Add Channel",self.cur_server,self.cur_domain)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_add_channel(self.cur_server,self.cur_domain,dialog.name.get_text())==True:
          self.updatechannellist()
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error2")
      else:
        self.statusbar.push(self.messageid,"Error")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    
  def delete_channel_intern(self,_delete_channel):
    returnstate=False
    dialog = scnDeletionDialog(self.win,self.cur_server,self.cur_domain,_delete_channel)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_channel(self.cur_server,self.cur_domain,_delete_channel)==True:
          returnstate=True
          self.statusbar.push(self.messageid,"Success")
          #returnel=Gtk.Label("Success")
        else:
          self.statusbar.push(self.messageid,"Error, something happened")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    return returnstate

  def delete_channel(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.delete_channel_intern(temp[0][temp[1]][1])==True:
      self.updatechannellist()


  def delete_channel2(self, *args):
    if self.delete_channel_intern(self.cur_domain)==True:
      self.update(self.cur_channel)
      self.updatechannellist()



  
  def update_message(self,*args):
    temp=self.builder.get_object("domainmessage")
    bounds=temp.get_bounds()
    self.linkback.main.c_update_message(self.cur_server,self.cur_domain,temp.get_text(bounds[0],bounds[1],True))

  def update_server_message(self,*args):
    temp=self.builder.get_object("servermessage")
    bounds=temp.get_bounds()
    self.linkback.main.c_update_message(self.cur_server,"admin",temp.get_text(bounds[0],bounds[1],True))
    
  def reset_message(self,*args):
    temp=self.builder.get_object("domainmessage")
    temp.set_text(self.linkback.main.c_get_domain_message(self.cur_server,self.cur_domain))

  def reset_server_message(self,*args):
    temp=self.builder.get_object("servermessage")
    temp.set_text(self.linkback.main.c_get_domain_message(self.cur_server,"admin"))

  def renew_secret(self,*args):
    self.linkback.main.c_update_secret(self.cur_server,self.cur_domain,self.cur_channel)

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
