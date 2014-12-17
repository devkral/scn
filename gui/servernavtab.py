
from gi.repository import Gtk,Gdk
from gui.dialogs import scnDeletionDialog,scnServerAddDialog,scnServerEditDialog,scnNameAddDialog
from scn_base import check_invalid_s,sepc,sepu,scn_gen_ncert

import hashlib
import logging

class servernavtab(object):
  confirm_button_id=None
  reset_button_id=None

  def __init__(self):
    self.navcontent=self.builder.get_object("navcontent")
    self.navbox=self.builder.get_object("navbox")
    renderer = Gtk.CellRendererText()
    renderer2 = Gtk.CellRendererText()
    tempelem = Gtk.TreeViewColumn("", renderer2, text=0)
    self.listelems = Gtk.TreeViewColumn("Title", renderer, text=1)
    self.navbox.append_column(tempelem)
    self.navbox.append_column(self.listelems)
  
  def get_cur_channel(self):
    if self.cur_channel is not None:
      return self.cur_channel
    elif self.cur_server is not None and self.cur_domain is not None:
      temp=self.navbox.get_selection().get_selected()
      if temp[1] is None:
        return None
      return temp[0][temp[1]][1]
    else:
      return None  
      
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
    self.navbox.get_selection().select_path(Gtk.TreePath.new_first())
    return True 

  def updatedomainlist(self, *args):
    _tremote_domains=self.linkback.main.c_list_domains(self.cur_server)
    if _tremote_domains is None:
      return False
    # more validation would be better
    _tadmin_domains=self.linkback.main.scn_servers.list_domains(self.cur_server,"admin",False)
    _tlocal_domains=self.linkback.main.scn_servers.list_domains(self.cur_server,False)
    self.navbox.show()
    self.listelems.set_title("Domain")
    self.navcontent.clear()
    len_remote=len(_tremote_domains)
    count=0
    for elem in _tremote_domains+_tlocal_domains:
      prefix=""
      if count>=len_remote: # if in tlocal_domains
        if elem not in _tremote_domains:
          prefix+="l"
        else:
          count+=1
          continue
      if elem in _tadmin_domains:
        prefix+="a"
      elif elem in _tlocal_domains:
        prefix+="n"
      self.navcontent.append((prefix,elem))
      count+=1
    self.navbox.get_selection().select_path(Gtk.TreePath.new_first())
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
    self.navbox.get_selection().select_path(Gtk.TreePath.new_first())
    return True
      
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
    self.navbox.get_selection().select_path(Gtk.TreePath.new_first())
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

    channelfold=self.builder.get_object("dropinchannelcontext2")
    if len(channelfold.get_children())>=1:
      channelfold.remove(channelfold.get_children()[0])
    channelf=self.builder.get_object("dropinchannelcontext1")
    if len(channelf.get_children())>=1:
      channelf.remove(channelf.get_children()[0])
    channelf.add(self.genchannelcontext())

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

    tnode=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin")
    if tnode is None:
      is_admin=False
    else:
      is_admin=True
    if tnode is not None and tnode[4]==True:
      is_admin=self.linkback.main.c_update_pending(self.cur_server,self.cur_domain,"admin")
      
    #hide controls if client has no admin rights
    if is_admin==True:
      domainmessage.set_editable(True)
      self.builder.get_object("domainmessagecontrols").show()
      self.builder.get_object("addchannelb").show()
      self.builder.get_object("delchannelb").show()
    else:
      self.builder.get_object("domainmessagecontrols").hide()
      self.builder.get_object("addchannelb").hide()
      self.builder.get_object("delchannelb").hide()
    
      
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

    #hide renew secret if no secret is available or it isn't confirmed
    tnode=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,self.cur_channel)
    if tnode is not None: # and tnode[4]==False:
      self.builder.get_object("renewsecret").show()
      self.builder.get_object("deleteself").show()
    else:
      self.builder.get_object("renewsecret").hide()
      self.builder.get_object("deleteself").hide()
      
    #hide admin options for non-admins
    tadmin=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin")
    if tadmin is None or tadmin[4]==True:
      self.builder.get_object("pinchannelorderb").hide()
      self.builder.get_object("addnodeb").hide()
      self.builder.get_object("delnodeb1").hide()
    else:
      self.builder.get_object("pinchannelorderb").show()
      self.builder.get_object("addnodeb").show()
      self.builder.get_object("delnodeb1").show()
    
    
    channelfold=self.builder.get_object("dropinchannelcontext1")
    if len(channelfold.get_children())>=1:
      channelfold.remove(channelfold.get_children()[0])
    channelf=self.builder.get_object("dropinchannelcontext2")
    if len(channelf.get_children())>=1:
      channelf.remove(channelf.get_children()[0])
    channelf.add(self.genchannelcontext())
    self.fill_node_data()
    #self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_channel)
    #self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_channel)  

  def genchannelcontext(self):
    _channel=self.get_cur_channel()
    if _channel is None:
      return Gtk.Label("")
    self.update_request_field(_channel)
    _channeldata=self.builder.get_object("channeldatadropin")
    if len(_channeldata.get_children())>=1:
      _channeldata.remove(_channeldata.get_children()[0])
    if _channel=="admin":
      self.builder.get_object("channel1").set_text("Admin")
      self.builder.get_object("channel2").set_text("Admin")
      atemp=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin")
      if atemp is not None and bool(atemp[4])==False:
        _channeldata.add(self.builder.get_object("adminchannel"))
      else:
        pass
    elif _channel=="special":# or _channel in self.linkback.main.special_channels
      self.builder.get_object("channel1").set_text("Special")
      self.builder.get_object("channel2").set_text("Special")
      if self.scn_servers.get_channel(self.cur_server,self.cur_domain,"special") is None and \
         self.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin") is None:
        #noperm=self.builder.get_object("nopermissionchannel")
        #self.gen_req(self.builder.get_object("genrequestdropin1"))
        #return noperm
        pass
      _channeldata.add(self.builder.get_object("specialchannel"))
    elif _channel=="main":
      self.builder.get_object("channel1").set_text("Main")
      self.builder.get_object("channel2").set_text("Main")
      _channeldata.add(self.builder.get_object("mainchannel"))
    elif _channel=="notify":
      self.builder.get_object("channel1").set_text("Notify")
      self.builder.get_object("channel2").set_text("Notify")
      _channeldata.add(self.builder.get_object("notifychannel"))
    else:
      self.builder.get_object("channel1").set_text("__"+_channel)
      self.builder.get_object("channel2").set_text("__"+_channel)
      _channeldata.add(self.builder.get_object("genericchannel"))
    return self.builder.get_object("channelbase")

      
  def add_req(self,*args):
    _channel=self.get_cur_channel()
    if _channel is None:
      return
    tempnode=self.linkback.main.scn_servers.get_channel(self.cur_server, 
    self.cur_domain, _channel)
    #protection against double add if some gui runs wild
    if tempnode is None:
      self.linkback.main.c_create_serve(self.cur_server,self.cur_domain,_channel)
    self.update_request_field(_channel)

  def update_request_field(self,_channel):
    _dropinob=self.builder.get_object("genrequestdropin1")
    #cleanup
    if len(_dropinob.get_children())==1:
      _dropinob.remove(_dropinob.get_children()[0])
    tempnode=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,_channel)
    if tempnode is None:
      _dropinob.add(self.builder.get_object("genrequestb"))
      self._cache_request_channel=None
      self._cache_request_hashes=None
    elif bool(tempnode[4])==False:
      self._cache_request_channel=None
      self._cache_request_hashes=None
      # if special channel deactivate completely elsewise
      # offer menu to select connect type
      if _channel=="admin":
        _dropinob.add(self.builder.get_object("alreadyreqdropel"))
    else:
      _dropinob.add(self.builder.get_object("requestdropelem"))
      #TODO: ease for admins
      #tempnodeadmin=self.linkback.main.scn_servers.get_channel(self.cur_server,self.cur_domain,"admin")
      namefield=self.builder.get_object("usreqname")
      if namefield.get_text().strip()=="":
        namefield.set_text(self.linkback.main.name)
      domaincerthash=scn_gen_ncert(self.cur_domain,self.linkback.main.pub_cert)
      hashed_secret=hashlib.sha256(tempnode[2]).hexdigest()
      self._cache_request_channel=_channel
      self._cache_request_hashes=str(hashed_secret)+","+domaincerthash
      self.fill_req_result()
      
  def fill_req_result(self,*args):
    if self._cache_request_channel is None or self._cache_request_hashes is None:
      return
    tempname=self.builder.get_object("usreqname").get_text()
    self.builder.get_object("usreqresult").set_text(self._cache_request_channel+","+tempname+","+self._cache_request_hashes)


    
  def fill_node_data(self,*args):
    tempnodeid=self.navbox.get_selection().get_selected()
    if tempnodeid[1] is None:
      return
    else:
      try:
        tempnodeid=int(tempnodeid[0][tempnodeid[1]][0])
      except Exception:
        return
    
    tempnodel=self.linkback.main.c_get_channel_addr(self.cur_server,self.cur_domain,self.cur_channel,tempnodeid)
    addrtype=self.builder.get_object("addrtypelabel")
    addr=self.builder.get_object("addrlabel")
    nodehash=self.builder.get_object("nodecerthashlabel")
    if bool(tempnodel)==False:
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
    
  def select_chadmin(self,*args):
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,self.cur_domain,"admin")
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
    channelfold=self.builder.get_object("dropinchannelcontext2")
    if len(channelfold.get_children())>=1:
      channelfold.remove(channelfold.get_children()[0])
    channelf=self.builder.get_object("dropinchannelcontext1")
    if len(channelf.get_children())>=1:
      channelf.remove(channelf.get_children()[0])
    channelf.add(self.genchannelcontext())
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
          logging.error("Invalid characters")
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

  def pin_nodes(self,*args):
    sorting_permutation=[] # first applied lesson of Info3
    for nodeiter in self.navcontent:
      #if self.navcontent.iter_has_child(nodeiter):
      sorting_permutation += [int(nodeiter[0]),]
    tsecretlistin=self.linkback.main.c_get_channel_secrethash(self.cur_server,self.cur_domain,self.cur_channel)
    if tsecretlistin is None:
      return
    tsecretlistout=""
    for spelem in sorting_permutation:
      tsecretlistout+=tsecretlistin[spelem][0]+sepu+tsecretlistin[spelem][1]+sepu+tsecretlistin[spelem][2]+sepc
    
    self.linkback.main.c_update_channel(self.cur_server,self.cur_domain,self.cur_channel,tsecretlistout[:-1])

  def delete_node(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    searchedposition=int(temp[0][temp[1]][0])
    nname=temp[0][temp[1]][1]
    tsecretlistin=self.linkback.main.c_get_channel_secrethash(self.cur_server,self.cur_domain,self.cur_channel)
    if tsecretlistin is None:
      self.statusbar.push(self.messageid,"Error, getting secret list")
      return
    tsecretlistout=""
    count=0
    dialog = scnDeletionDialog(self.win,self.cur_server,self.cur_domain,self.cur_channel,nname)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        #returnel=Gtk.Label("Success")  
        for elem in tsecretlistin:
          if count!=searchedposition:
            tsecretlistout+=elem[0]+sepu+elem[1]+sepu+elem[2]+sepc
            count+=1
        self.linkback.main.c_update_channel(self.cur_server,self.cur_domain,self.cur_channel,tsecretlistout[:-1])
      else:
        self.statusbar.push(self.messageid,"Error, something happened")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    

  def delete_self(self,*args):
    dialog = scnSelfDeletionDialog(self.win,self.cur_server,self.cur_domain,self.cur_channel)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_del_serve(self.cur_server,self.cur_domain,self.cur_channel)==False:
          self.statusbar.push(self.messageid,"Error deleting self")
          #TODO: ask for force
        else:
          self.statusbar.push(self.messageid,"Success")
          self.updatenodelist()
      else:
        self.statusbar.push(self.messageid,"Error, something happened")
    except Exception as e:
      self.statusbar.push(self.messageid,str(e))
    dialog.destroy()
    
    
  def load_request(self,*args):
    temp=self.builder.get_object("reqaduser").get_text()
    self.builder.get_object("reqaduser").set_text("")
    t=temp.split(",")
    if len(t)!=4:
      self.statusbar.push(self.messageid,"Error, invalid request")
      return
    reqadnamein,reqadchannel,reqadshashin,reqadphashin=t
    self.builder.get_object("reqadname").set_text(reqadnamein)
    self.builder.get_object("reqadchannel").set_text(reqadchannel)
    self.builder.get_object("reqadphash").set_text(reqadphashin) # hash public
    self.builder.get_object("reqadshash").set_text(reqadshashin) # hash secret
    self.builder.get_object("reqadnodeposition").set_value(0)
  
  def confirm_request(self,*args): #reqadname,reqadhash,reqadnodeposition
    aname=self.builder.get_object("reqadname").get_text()
    bhash=self.builder.get_object("reqadphash").get_text() # hash public
    chash=self.builder.get_object("reqadshash").get_text() # hash secret
    dpos=self.builder.get_object("reqadnodeposition").get_value_as_int()
    ctemp=self.get_cur_channel()
    if ctemp is None:
      return
    tsecretlistin=self.linkback.main.c_get_channel_secrethash(self.cur_server,self.cur_domain,ctemp)
    if tsecretlistin is None:
      return
    tsecretlistout=""
    count=0
    for elem in tsecretlistin:
      if count!=dpos:
        tsecretlistout+=elem[0]+sepu+elem[1]+sepu+elem[2]+sepc
      else:
        tsecretlistout+=aname+sepu+bhash+chash+sepc
        tsecretlistout+=elem[0]+sepu+elem[1]+sepu+elem[2]+sepc
    if dpos>=len(tsecretlistin):
      tsecretlistout+=aname+sepu+bhash+sepu+chash+sepc
    self.linkback.main.c_update_channel(self.cur_server,self.cur_domain,ctemp,tsecretlistout[:-1])

  def select_all_clipboard(self,*args):
    t=self.builder.get_object("usreqresult")
    t.select_region(0,len(t.get_text()))
    
    self.clip.set_text(t.get_text(), -1)
