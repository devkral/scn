#! /usr/bin/env python3


import threading
import signal
import sys

from scn_client import client_master,scn_client,scn_server_client,scn_sock_client
from gi.repository import Gtk,Gdk

from scn_config import default_config_folder, scn_host

cm=client_master()


#normalflag=Gtk.StateFlags.NORMAL|Gtk.StateFlags.ACTIVE
icons=Gtk.IconTheme.get_default()


#TODO: redesign: use splitscreen: a small tree with servernames,
#a subwindow tree with names on server (compressed)
#a subwindow with actions

class scnDeletionDialog(Gtk.Dialog):
  def __init__(self, _parent, _server,_name=None,_service=None):
    Gtk.Dialog.__init__(self, "Confirm Deletion", _parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    if _name is not None and _service is not None:
      label=Gtk.Label("Shall service \""+_service+"\" of "+_server+"/"+_name+" be deleted?")
    elif _name is not None and _service is None:
      label=Gtk.Label("Shall name \""+_name+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()


class scnServerEditDialog(Gtk.Dialog):
  servername=None
  urlname=None
  def __init__(self, _parent, _title, _servername,_url=""):
    self.parent=_parent
    self.servername=Gtk.Entry()
    self.servername.set_hexpand(True)
    self.servername.set_text(_servername)
    self.url=Gtk.Entry()
    self.url.set_hexpand(True)
    self.url.set_text(_url)
    
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
    turl=Gtk.Label("Url: ")
    turl.set_halign(Gtk.Align.END)
    cont.attach(turl,0,1,1,1)
    cont.attach(self.url,1,1,1,1)

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



class scnPageNavigation(Gtk.Grid):
  parent=None
  linkback=None

  cur_server=None #use only after set by scnupdate
  cur_name=None #use only after set by scnupdate
  cur_service=None #use only after set by scnupdate
  
  def __init__(self,_parent):
    Gtk.Grid.__init__(self)
    self.parent=_parent
    self.linkback=self.parent.linkback

    self.set_row_spacing(2)
    self.set_margin_left(5)
    self.set_margin_right(5)
    self.set_margin_top(5)
    self.set_margin_bottom(2)

    self.navbar=Gtk.Entry()
    self.navbar.connect("activate",self.navbarupdate)
    self.navcontent=Gtk.ListStore(str)
    self.navbox=Gtk.TreeView(self.navcontent)
    renderer = Gtk.CellRendererText()
    self.listelems = Gtk.TreeViewColumn("Title", renderer, text=0)
    self.navbox.append_column(self.listelems)
    self.navbox.get_selection().set_mode(Gtk.SelectionMode.BROWSE)
    self.navbox.set_vexpand(True)
    self.navcontextmain=Gtk.Frame()
    #self.navcontextmain.set_margin_right(5)
    self.navcontextmain.set_hexpand(True)
    self.navcontextmain.set_shadow_type(Gtk.ShadowType.NONE)

    navcontainer=Gtk.Grid()
    navcontainer.set_column_spacing(2)

    #navcontainer.set_margin_top(2)
    #navcontainer.set_margin_left(5)
    #navcontainer.set_margin_right(5)
    labelnavbar=Gtk.Label("Navigation: ")
    navbarconfirm=Gtk.Button("OK")
    navbarconfirm.connect("clicked",self.navbarupdate)
    navcontainer.attach(labelnavbar,0,0,1,1)
    self.navbar.set_hexpand (True)
    navcontainer.attach(self.navbar,1,0,1,1)
    navcontainer.attach(navbarconfirm,2,0,1,1)

    self.attach(navcontainer,0,0,2,1)
    self.attach(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL),0,1,2,1)

    frame_nav=Gtk.Frame()
    frame_nav.add(self.navbox)
    frame_nav.set_margin_left(5)
    frame_nav.set_margin_right(5)

    #self.attach(self.navcontextsmall,0,2,1,1)
    self.attach(frame_nav,0,2,1,1)

    
    self.navcontextmain.set_label_align(0.1,0.8)
    self.attach(self.navcontextmain,1,2,1,1)
    self.update()


  def update(self,_server=None,_name=None,_service=None):
    self.cur_server=_server
    self.cur_name=_name
    self.cur_service=_service
    if _service is not None:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
      
      self.navbar.set_text(self.cur_server+"/"+self.cur_name+"/"+self.cur_service)
      self.buildservicegui()

    elif _name is not None:
      self.navbar.set_text(self.cur_server+"/"+self.cur_name+"/")
      self.buildnamegui()

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

  def updateserverlist(self):
    temp2=self.linkback.main.scn_servers.list_nodes()
    if temp2 is None:
      return False
    self.listelems.set_title("Server")
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.5, 0.5, 1, 1))
    self.navbox.show()
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem[0],))

  def updatenamelist(self):
    temp_remote=self.linkback.main.c_list_names(self.cur_server)
    if temp_remote is None:
      return False
    temp_local=self.linkback.main.scn_servers.list_names(self.cur_server)
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0.7, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Name")
    self.navcontent.clear()

    for elem in temp_local:
      if elem[0] not in temp_remote:
        self.navcontent.append(("local: "+elem[0],))
    for elem in temp_remote:
      self.navcontent.append((elem,))
    return True

  def updateservicelist(self):
    temp2=self.linkback.main.c_list_services(self.cur_server,self.cur_name)
    if temp2 is None:
      return False
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Service")
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem,))

  def buildNonegui(self):
    if self.updateserverlist()==False:
      self.state_widget.set_text("Error loading servers")
    #label counts as child, so ignore it
    if len(self.navcontextmain.get_children())==1:
      #print(self.navcontextmain.get_children())
      self.navcontextmain.get_children()[0].destroy()
      #self.navcontextmain.set_label("Context")
    #build grid for contextarea
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)
    contextcont.set_row_spacing(2)
    #contextcont.set_border_width(3)
    contextcont.attach(Gtk.Label("Actions:"),0,0,1,1)
    addServerButton1=Gtk.Button("Add Server")
    addServerButton1.connect("clicked", self.add_server)
    contextcont.attach(addServerButton1,0,1,1,1)
    deleteServerButton1=Gtk.Button("Delete Server")
    deleteServerButton1.connect("clicked", self.delete_server)
    contextcont.attach(deleteServerButton1,0,2,1,1)
    
    editServerButton1=Gtk.Button("Edit Server")
    editServerButton1.connect("clicked", self.edit_server2)
    contextcont.attach(editServerButton1,0,3,1,1)

    goServerButton1=Gtk.Button("Use Server")
    goServerButton1.connect("clicked", self.select_server)
    contextcont.attach(goServerButton1,0,4,1,1)
    self.navcontextmain.show_all()


  def buildservergui(self):
    if self.updatenamelist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return

    if len(self.navcontextmain.get_children())==1:
      #print(self.navcontextmain.get_children())
      self.navcontextmain.get_children()[0].destroy()
      #print(self.navcontextmain.get_children())
    #build grid for contextarea
    contextcont=Gtk.Grid()
    contextcont.set_column_spacing(2)
    self.navcontextmain.add(contextcont)

    
    ### server actions ###

    servercont_f=Gtk.Frame()
    servercont_f.set_label("Server actions")
    servercont=Gtk.Grid()
    servercont.set_row_spacing(2)
    servercont.set_border_width(2)
    servercont_f.add(servercont)
    contextcont.attach(servercont_f,0,1,1,1)

    deleteServerButton3=Gtk.Button("Delete server")
    deleteServerButton3.connect("clicked", self.delete_server2)
    servercont.attach(deleteServerButton3,0,0,1,1)
    
    editServerButton1=Gtk.Button("Edit Server")
    editServerButton1.connect("clicked", self.edit_server2)
    servercont.attach(editServerButton1,0,1,1,1)

    
    goNoneButton2=Gtk.Button("Go back")
    goNoneButton2.connect("clicked", self.goback_none)
    servercont.attach(goNoneButton2,0,2,1,1)

    goNameButton1=Gtk.Button("Use Name")
    goNameButton1.connect("clicked", self.select_name)
    servercont.attach(goNameButton1,0,3,1,1)
    
    ### name actions ###

    namecont_f=Gtk.Frame()
    namecont_f.set_label("Name actions")
    namecont=Gtk.Grid()
    namecont.set_row_spacing(2)
    namecont.set_border_width(2)
    namecont_f.add(namecont)
    contextcont.attach(namecont_f,0,0,1,1)


    addNameButton1=Gtk.Button("Register Name")
    addNameButton1.connect("clicked", self.register_name)
    namecont.attach(addNameButton1,0,0,1,1)
    

    deleteNameButton3=Gtk.Button("Delete Name")
    deleteNameButton3.connect("clicked", self.delete_name)
    namecont.attach(deleteNameButton3,0,1,1,1)


    ### space for message
    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Server Message")
    tempmessage=self.linkback.main.c_get_server_message(self.cur_server)
    tempshowlabel=Gtk.Label()
    tempshowlabel.set_halign(Gtk.Align.START)
    tempshowlabel.set_valign(Gtk.Align.START)
    tempshowlabel.set_hexpand(True)
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,1,0,1,1)

#    self.servercont_f.show_all()
#    self.namecont_f.show_all()
    self.navcontextmain.show_all()

  def buildnamegui(self):
    
    if self.updateservicelist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildservergui()
      return

    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
    #build grid for contextarea
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)

    namecont_f=Gtk.Frame()
    namecont_f.set_label("Name actions")
    namecont=Gtk.Grid()
    namecont.set_row_spacing(2)
    namecont.set_border_width(2)
    namecont_f.add(namecont)
    contextcont.attach(namecont_f,0,0,1,1)


    goServerButton2=Gtk.Button("Go back")
    goServerButton2.connect("clicked", self.goback_server)
    namecont.attach(goServerButton2,0,2,2,1)


    servicecont_f=Gtk.Frame()
    servicecont_f.set_label("Service actions")
    servicecont=Gtk.Grid()
    servicecont.set_row_spacing(2)
    servicecont.set_border_width(2)
    servicecont_f.add(servicecont)
    contextcont.attach(servicecont_f,0,0,1,1)


    reqServiceButton1=Gtk.Button("Create Serve Request")
    reqServiceButton1.connect("clicked", self.select_service)
    servicecont.attach(reqServiceButton1,0,0,1,1)


    self.ServiceRequest_entry=Gtk.Entry()
    #reqServiceEntry1.connect("clicked", self.select_service)
    servicecont.attach(self.ServiceRequest_entry,1,0,1,1)

    delreqServiceButton1=Gtk.Button("Delete Serve Request")
    delreqServiceButton1.connect("clicked", self.select_service)
    namecont.attach(delreqServiceButton1,0,1,2,1)


    goServiceButton1=Gtk.Button("Use Service")
    goServiceButton1.connect("clicked", self.select_service)
    servicecont.attach(goServiceButton1,0,2,2,1)


    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Message")
    tempmessage=self.linkback.main.c_get_name_message(self.cur_server,self.cur_name)
    tempshowlabel=Gtk.Label()
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,0,1,1,1)


    self.navcontextmain.show_all()

  def buildservicegui(self):
    if self.cur_server is None or self.cur_name is None or self.cur_service is None:
      self.buildnamegui()
      return
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 0.7, 0.7, 1))
    self.listelems.set_title("")
    self.navcontent.clear()
    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)
    goNameButton2=Gtk.Button("Go back")
    goNameButton2.connect("clicked", self.goback_name)
    contextcont.attach(goNameButton2,0,0,1,1)
    temp=self.genservicecontext(self.cur_service)
    temp.set_vexpand(True)
    temp.set_hexpand(True)
    contextcont.attach(temp,1,0,1,1)
    self.navcontextmain.show_all()
    

  def genservicecontext(self,_service):
    return Gtk.Label("Placeholder")


  ### select section  ###
  def goback_none(self,*args):
    self.update()

  def select_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(temp[0][temp[1]][0])

  def goback_server(self,*args):
    self.update(self.cur_server)

  def select_name(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,temp[0][temp[1]][0])

  def goback_name(self,*args):
    self.update(self.cur_server,self.cur_name) 
  
  def select_service(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,self.cur_name,temp[0][temp[1]][0])
    
  ### server section ###

  def delete_server_intern(self,_delete_server):
    returnstate=False
    dialog = scnDeletionDialog(self.parent,_delete_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_server(_delete_server)==True:
          self.updateserverlist()
          returnstate=True
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    return returnstate

  #get server by navbox
  def delete_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.delete_server_intern(temp[0][temp[1]][0])

  #get server by current selection
  def delete_server2(self,*args):
    if self.cur_server is None:
      return
    if self.delete_server_intern(self.cur_server)==True:
      self.update()


  def add_server(self,*args):
    dialog = scnServerEditDialog(self.parent,"Add new server","","")
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_add_server(dialog.servername.get_text(),dialog.url.get_text())==True:
          self.updateserverlist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    
  def edit_server2(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.edit_server_intern(temp[0][temp[1]][0])==True:
      self.updateserverlist()

  def edit_server(self,*args):
    if self.edit_server_intern(self.cur_server)==True:
      self.update()

  def edit_server_intern(self,_server):
    returnstate=False
    temp=self.linkback.main.scn_servers.get_node(_server)
    if temp is None:
      self.parent.state_widget.set_text("Not exists")
      return
    #todo: show cert
    dialog = scnServerEditDialog(self.parent,"Edit server",_server,temp[0])
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if dialog.servername!=_server:
          self.linkback.main.scn_servers.update_node_name(_server,dialog.servername.get_text())
          
        if self.linkback.main.c_update_server(dialog.servername.get_text(),dialog.url.get_text())==True:
          returnstate=True
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
      else:
          self.parent.state_widget.set_text("Aborted")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    return returnstate

  def register_name(self,*args):
    dialog = scnNameAddDialog(self.parent,"Register",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_register_name(self.cur_server,dialog.name.get_text())==True:
          self.updatenamelist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
      else:
        self.parent.state_widget.set_text("Error")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()


  def delete_name_intern(self,_delete_name):
    returnstate=False
    dialog = scnDeletionDialog(self.parent,self.cur_server,_delete_name)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_name(self.cur_server,_delete_name)==True:
          self.linkback.main.scn_servers.del_name(self.cur_server,_delete_name)
          self.parent.state_widget.set_text("Success")
          returnstate=True
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
        
          
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    if returnstate==False:
      pass
      #delete anyway dialog
      #self.linkback.main.scn_servers.del_name(self.cur_server,_delete_name)

    return returnstate

  def delete_name(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.delete_name_intern(temp[0][temp[1]][0])==True:
      self.updatenamelist()


  def delete_name2(self, *args):
    if self.delete_name_intern(self.cur_name)==True:
      self.update(self.cur_server)
      self.updatenamelist()
  ### name/service section ###

  def add_service(self,*args):
    dialog = scnNameAddDialog(self.parent,"Add Service",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if True==True:#self.linkback.main.c_register_name(self.cur_server,dialog.name.get_text())==True:
          self.updateservicelist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
      else:
        self.parent.state_widget.set_text("Error")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()


  def delete_service_intern(self,_delete_service):
    returnstate=False
    dialog = scnDeletionDialog(self.parent,self.cur_server,self.cur_name,_delete_service)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_service(self.cur_server,self.cur_name,_delete_service)==True:
          returnstate=True
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error, something happened")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()
    return returnstate

  def delete_service(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.delete_service_intern(temp[0][temp[1]][0])==True:
      self.updateservicelist()


  def delete_service2(self, *args):
    if self.delete_service_intern(self.cur_name)==True:
      self.update(self.cur_service)
      self.updateservicelist()


"""
class scnPageServers(Gtk.Frame):
  parent=None
  def __init__(self,_parent):
    Gtk.Frame.__init__(self)
    self.parent=_parent
    cont=Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    self.serverlist=Gtk.ListBox()#orientation=Gtk.Orientation.VERTICAL)
    cont.pack_start(self.serverlist,True,True,0)
    controls=Gtk.Grid()
    cont.pack_start(controls,True,True,0)
    add_server_button=Gtk.Button("Add Server")
    add_server_button.connect("clicked", self.add_server)
    controls.attach(add_server_button,0,0,1,1)
    self.add(cont)
    self.update()
    self.show_all()
    
  def update(self):
    for elem in self.parent.linkback.main.scn_servers.list_nodes():
      self.serverlist.add(scnServerNode(elem[0],self.parent))

  def add_server(self,button):
    pass"""

class scnPageFriends(Gtk.Grid):
  parent=None
  linkback=None
  def __init__(self,_parent):
    Gtk.Grid.__init__(self)
    self.parent=_parent
    self.linkback=self.parent.linkback
    self.attach(Gtk.Label("Not implemented yet"),0,0,1,1)


class scnGUI(Gtk.Window):
  confirm_button_id=None
  reset_button_id=None
  state_widget=None
  note_main=None
  linkback=None
  def __init__(self,_linkback):
    Gtk.Window.__init__(self, title="Secure Communication Nodes")
    self.linkback=_linkback
    self.resize(600,400)
    self.set_icon_from_file("icon.png")

    main_wid=Gtk.Grid()

    self.note_switch=Gtk.Notebook()
    self.note_switch.set_margin_left(5)
    self.note_switch.set_margin_right(5)
    self.note_switch.set_hexpand(True)
    self.note_switch.set_vexpand(True)
    main_wid.attach(self.note_switch,0,0,1,1)
    self.state_widget=Gtk.Label("")
    self.state_widget.set_hexpand(True)
    self.state_widget.set_margin_top(5)
    main_wid.attach(self.state_widget,0,1,1,1)

    #add=Gtk.Button(label="add")
    #add.connect("clicked", self.click_add)
    
    #.set_margin_left(5)
    #self.confirm_button=Gtk.Button("Apply")
    #self.reset_button=Gtk.Button("Reset")


    #self.main_grid.set_column_spacing(10)
    #self.main_grid.set_row_spacing(20)
    self.note_switch.append_page(scnPageNavigation(self),Gtk.Label("Server Navigation"))
#    self.note_switch.append_page(scnPageServers(self),Gtk.Label("Servermanagement"))
    self.note_switch.append_page(scnPageFriends(self),Gtk.Label("Friends"))
    
    self.note_switch.append_page(Gtk.Label("Not implemented yet"),Gtk.Label("Settings"))
    self.add(main_wid)


win=None

def signal_handler(_signal, frame):
  #win.close()
  win.destroy()
  Gtk.main_quit()
  #app.close()
  sys.exit(0)

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

  win = scnGUI(cm)
  
  win.connect("delete-event", Gtk.main_quit)
  #win.connect("destroy", Gtk.main_quit) 

  win.show_all()
  Gtk.main()
  
  sys.exit(0)
