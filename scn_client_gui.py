#! /usr/bin/env python3


import threading
import signal
import sys

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
  def __init__(self, _parent, _server,_domain=None,_service=None):
    Gtk.Dialog.__init__(self, "Confirm Deletion", _parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    if _domain is not None and _service is not None:
      label=Gtk.Label("Shall service \""+_service+"\" of "+_server+"/"+_domain+" be deleted?")
    elif _domain is not None and _service is None:
      label=Gtk.Label("Shall domain \""+_domain+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()


class scnServerEditDialog(Gtk.Dialog):
  servername=None
  certname=None
  certchange=None
  url=None
  def __init__(self, _parent, _title, _servername,_serverinfo=None):
    self.parent=_parent
    self.servername=Gtk.Entry()
    self.servername.set_hexpand(True)
    self.servername.set_text(_servername)
    self.certname=Gtk.Entry()
    self.certname.set_hexpand(True)
    if _serverinfo is None:
      self.certname.set_text(_servername)
    else:
      self.certname.set_text(_serverinfo[2])
    self.certchange=Gtk.CheckButton(label="Change to cert")
    self.url=Gtk.Entry()
    self.url.set_hexpand(True)
    if _serverinfo is not None:
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
    if _serverinfo is not None:
      cont.attach(self.certchange,2,1,1)
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



class scnPageNavigation(Gtk.Grid):
  parent=None
  linkback=None

  cur_server=None #use only after set by scnupdate
  cur_domain=None #use only after set by scnupdate
  cur_service=None #use only after set by scnupdate
  box_select_handler_id=None
  box_activate_handler_id=None

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
    self.navbox.set_activate_on_single_click(False)
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
    self.navbar.connect("activate",self.navbarupdate)
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


  def update(self,_server=None,_domain=None,_service=None):
    if _server=="":
      _server=None
    self.cur_server=_server
    self.cur_domain=_domain
    self.cur_service=_service

      #self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    if _service is not None:
      self.navbar.set_text(self.cur_server+"/"+self.cur_domain+"/"+self.cur_service)
      self.buildservicegui()

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

  def updateserverlist(self):
    temp2=self.linkback.main.scn_servers.list_servers()
    if temp2 is None:
      return False
    self.listelems.set_title("Server")
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.5, 0.5, 1, 1))
    self.navbox.show()
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem[0],))

  def updatedomainlist(self):
    temp_remote=self.linkback.main.c_list_domains(self.cur_server)
    if temp_remote is None:
      return False
    temp_local=self.linkback.main.scn_servers.list_domains(self.cur_server)
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0.7, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Domain")
    self.navcontent.clear()

    for elem in temp_local:
      if elem[0] not in temp_remote:
        self.navcontent.append(("local: "+elem[0],))
    for elem in temp_remote:
      self.navcontent.append((elem,))
    return True

  def updateservicelist(self):
    temp2=self.linkback.main.c_list_services(self.cur_server,self.cur_domain)
    if temp2 is None:
      return False
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.navbox.show()
    self.listelems.set_title("Service")
    self.navcontent.clear()
    for elem in temp2:
      self.navcontent.append((elem,))

  def updatenodelist(self):
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.2, 0.2, 0.2, 1))
    self.navbox.show()
    self.navcontent.clear()

    if self.cur_service=="admin":
      self.navbox.hide()
      #self.listelems.set_title("Admin")
      return True
    elif self.cur_service=="special" or \
       self.cur_service in self.special_services:
      self.navbox.hide()
#      self.listelems.set_title("Special")
      return True
    self.navbox.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 0.5, 0.5, 1))

    temp2=self.linkback.main.c_get_service(self.cur_server,self.cur_domain,self.cur_service)
    if temp2 is None:
      return False
    self.listelems.set_title("Users")
    for elem in temp2:
      self.navcontent.append((elem,))

  def buildNonegui(self):
    if self.updateserverlist()==False:
      self.parent.state_widget.set_text("Error loading servers")
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
      
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    #label counts as child, so ignore it
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
      #self.navcontextmain.set_label("Context")
    #build grid for contextarea
    contextcont=Gtk.Grid()
    self.navcontextmain.add(contextcont)
    contextcont.set_row_spacing(2)
    contextcont.set_column_spacing(2)
    #contextcont.set_border_width(2)

    navcont_f=Gtk.Frame()
    navcont_f.set_label("Navigation")
    navcont=Gtk.Grid()
    navcont.set_row_spacing(2)
    navcont.set_border_width(2)
    navcont_f.add(navcont)
    contextcont.attach(navcont_f,0,0,1,1)

    goServerButton1=Gtk.Button("Use Server")
    goServerButton1.connect("clicked", self.select_server)
    navcont.attach(goServerButton1,0,0,1,1)


    servercont_f=Gtk.Frame()
    servercont_f.set_label("Server Actions")
    servercont=Gtk.Grid()
    servercont.set_row_spacing(2)
    servercont.set_border_width(2)
    servercont_f.add(servercont)
    contextcont.attach(servercont_f,0,1,1,1)


    addServerButton1=Gtk.Button("Add Server")
    addServerButton1.connect("clicked", self.add_server)
    servercont.attach(addServerButton1,0,0,1,1)
    deleteServerButton1=Gtk.Button("Delete Server")
    deleteServerButton1.connect("clicked", self.delete_server)
    servercont.attach(deleteServerButton1,0,1,1,1)
    
    editServerButton1=Gtk.Button("Edit Server")
    editServerButton1.connect("clicked", self.edit_server2)
    servercont.attach(editServerButton1,0,2,1,1)


    #building frame showing message
    messagef2=Gtk.Frame()
    messagef2.set_label("Message")
    self.selectedservermessage=Gtk.Label()
    self.selectedservermessage.set_selectable(True)
    #self.linkback.main.c_get_domain_message(self.cur_server,self.cur_domain)
    
    self.selectedservermessage.set_halign(Gtk.Align.START)
    self.selectedservermessage.set_valign(Gtk.Align.START)
    self.selectedservermessage.set_hexpand(True)
    self.selectedservermessage.set_vexpand(True)
    messagef2.add(self.selectedservermessage)
    contextcont.attach(messagef2,1,1,1,1)
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_server)
    self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_server)
    self.navcontextmain.show_all()



  def buildservergui(self):
    if self.updatedomainlist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildNonegui()
      return
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None

    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    if len(self.navcontextmain.get_children())==1:
      #print(self.navcontextmain.get_children())
      self.navcontextmain.get_children()[0].destroy()
      #print(self.navcontextmain.get_children())
    #build grid for contextarea
    contextcont=Gtk.Grid()
    contextcont.set_column_spacing(2)
    contextcont.set_row_spacing(2)
    self.navcontextmain.add(contextcont)

    
    navcont_f=Gtk.Frame()
    navcont_f.set_label("Navigation")
    navcont=Gtk.Grid()
    navcont.set_row_spacing(2)
    navcont.set_border_width(2)
    navcont_f.add(navcont)
    contextcont.attach(navcont_f,0,0,1,1)
    
    
    goNoneButton2=Gtk.Button("Go back")
    goNoneButton2.connect("clicked", self.goback_none)
    navcont.attach(goNoneButton2,0,0,1,1)

    goDomainButton1=Gtk.Button("Use Domain")
    goDomainButton1.connect("clicked", self.select_domain)
    navcont.attach(goDomainButton1,0,1,1,1)

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

    
    
    ### domain actions ###

    domaincont_f=Gtk.Frame()
    domaincont_f.set_label("Domain actions")
    domaincont=Gtk.Grid()
    domaincont.set_row_spacing(2)
    domaincont.set_border_width(2)
    domaincont_f.add(domaincont)
    contextcont.attach(domaincont_f,0,2,1,1)


    addDomainButton1=Gtk.Button("Register Domain")
    addDomainButton1.connect("clicked", self.register_domain)
    domaincont.attach(addDomainButton1,0,0,1,1)
    

    deleteDomainButton3=Gtk.Button("Delete Domain")
    deleteDomainButton3.connect("clicked", self.delete_domain)
    domaincont.attach(deleteDomainButton3,0,1,1,1)


    ### space for message
    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Server Message")
    tempmessage=self.linkback.main.c_get_server_message(self.cur_server)
    tempshowlabel=Gtk.Label()
    tempshowlabel.set_selectable(True)
    tempshowlabel.set_halign(Gtk.Align.START)
    tempshowlabel.set_valign(Gtk.Align.START)
    tempshowlabel.set_hexpand(True)
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,1,0,1,1)

    #building frame showing message
    messagef2=Gtk.Frame()
    messagef2.set_label("Message")
    self.selecteddomainmessage=Gtk.Label()
    self.selecteddomainmessage.set_halign(Gtk.Align.START)
    self.selecteddomainmessage.set_valign(Gtk.Align.START)
    self.selecteddomainmessage.set_selectable(True)
    #self.linkback.main.c_get_domain_message(self.cur_server,self.cur_domain)
    self.selecteddomainmessage.set_hexpand(True)
    self.selecteddomainmessage.set_vexpand(True)
    messagef2.add(self.selecteddomainmessage)
    contextcont.attach(messagef2,1,1,1,2)
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_domain)
    
    self.box_select_handler_id=self.navbox.connect("row-activated",self.select_domain)

#    self.servercont_f.show_all()
#    self.domaincont_f.show_all()
    self.navcontextmain.show_all()

  def builddomaingui(self):
    
    if self.updateservicelist()==False:
      self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(1, 0, 0, 1))
      self.buildservergui()
      return
    if self.box_select_handler_id!=None:
      self.navbox.disconnect(self.box_select_handler_id)
      self.box_select_handler_id=None
    
    if self.box_activate_handler_id!=None:
      self.navbox.disconnect(self.box_activate_handler_id)
      self.box_activate_handler_id=None
    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
    #build grid for contextarea
    contextcont=Gtk.Grid()
    contextcont.set_column_spacing(2)
    contextcont.set_row_spacing(2)
    self.navcontextmain.add(contextcont)

    navcont_f=Gtk.Frame()
    navcont_f.set_label("Navigation")
    navcont=Gtk.Grid()
    navcont.set_row_spacing(2)
    navcont.set_border_width(2)
    navcont_f.add(navcont)
    contextcont.attach(navcont_f,0,0,1,1)

    goServiceButton1=Gtk.Button("Use Service")
    goServiceButton1.connect("clicked", self.select_service)
    navcont.attach(goServiceButton1,0,0,1,1)

    goServerButton2=Gtk.Button("Go back")
    goServerButton2.connect("clicked", self.goback_server)
    navcont.attach(goServerButton2,0,1,1,1)


    servicecont_f=Gtk.Frame()
    servicecont_f.set_label("Service actions")
    servicecont=Gtk.Grid()
    servicecont.set_row_spacing(2)
    servicecont.set_border_width(2)
    servicecont_f.add(servicecont)
    contextcont.attach(servicecont_f,0,1,1,1)

    if self.linkback.main.scn_servers.get_service(self.cur_server,self.cur_domain,"admin") is not None:
      addServiceButton2=Gtk.Button("Add service")
      addServiceButton2.connect("clicked", self.add_service)
      servicecont.attach(addServiceButton2,0,0,1,1)

      delServiceButton2=Gtk.Button("Delete service")
      delServiceButton2.connect("clicked", self.delete_service)
      servicecont.attach(delServiceButton2,0,1,1,1)

    #building frame showing message
    messagef=Gtk.Frame()
    messagef.set_label("Message")
    tempmessage=self.linkback.main.c_get_domain_message(self.cur_server,self.cur_domain)
    tempshowlabel=Gtk.Label()
    tempshowlabel.set_selectable(True)
    
    tempshowlabel.set_hexpand(True)
    tempshowlabel.set_halign(Gtk.Align.START)
    tempshowlabel.set_valign(Gtk.Align.START)
    messagef.add(tempshowlabel)
    if tempmessage is None or tempmessage=="":
      tempshowlabel.set_text("No message")
    else:
      tempshowlabel.set_text(tempmessage)
    contextcont.attach(messagef,1,0,1,1)
    self.servicef=Gtk.Frame()
    self.servicef.set_vexpand(True)
    self.servicef.set_hexpand(True)
    self.servicef.set_shadow_type(Gtk.ShadowType.NONE)
    contextcont.attach(self.servicef,1,1,1,1)
    self.box_select_handler_id=self.navbox.connect("cursor-changed",self.select_context_service)
    self.box_activate_handler_id=self.navbox.connect("row-activated",self.select_service)

    self.navcontextmain.show_all()


  ### service gui ###

  def buildservicegui(self):
    if self.cur_server is None or self.cur_domain is None or self.cur_service is None:
      self.builddomaingui()
      return
    #if self.box_select_handler_id!=None:
    #  self.navbox.disconnect(self.box_select_handler_id)
    #  self.box_select_handler_id=None
    self.updatenodelist()

    #label counts as child
    if len(self.navcontextmain.get_children())==1:
      self.navcontextmain.get_children()[0].destroy()
    
    contextcont=Gtk.Grid()
    contextcont.set_column_spacing(2)
    contextcont.set_row_spacing(2)
    self.navcontextmain.add(contextcont)


    managecont_f=Gtk.Frame()
    managecont_f.set_label("Basic Actions:")
    managecont=Gtk.Grid()
    managecont.set_row_spacing(2)
    managecont.set_border_width(2)
    managecont_f.add(managecont)
    contextcont.attach(managecont_f,0,0,1,1)

    if self.linkback.main.scn_servers.get_service(self.cur_server,self.cur_domain,self.cur_service) is None:
      createreqButton2=Gtk.Button("Create Request")
      createreqButton2.connect("clicked", self.goback_domain)
      managecont.attach(createreqButton2,0,0,1,1)

      self.ServiceRequest_entry=Gtk.Entry()
      managecont.attach(self.ServiceRequest_entry,1,0,1,1)
    else:

      delreqButton2=Gtk.Button("Delete Request")
      delreqButton2.connect("clicked", self.goback_domain)
      managecont.attach(delreqButton2,0,0,2,1)



    goDomainButton2=Gtk.Button("Go back")
    goDomainButton2.connect("clicked", self.goback_domain)
    managecont.attach(goDomainButton2,0,1,2,1)





    if self.linkback.main.scn_servers.get_service(self.cur_server,self.cur_domain,self.cur_service) is not None:
      selfmincont_f=Gtk.Frame()
      selfmincont_f.set_label("Self administration")
      selfmincont=Gtk.Grid()
      selfmincont.set_row_spacing(2)
      selfmincont.set_border_width(2)
      selfmincont_f.add(selfmincont)
      contextcont.attach(selfmincont_f,1,0,1,1)

    if self.linkback.main.scn_servers.get_service(self.cur_server,self.cur_domain,"admin") is not None:
      admincont_f=Gtk.Frame()
      admincont_f.set_label("Node management")
      admincont=Gtk.Grid()
      admincont.set_row_spacing(2)
      admincont.set_border_width(2)
      admincont_f.add(admincont)
      contextcont.attach(admincont_f,0,1,1,1)



    temp=self.genservicecontext(self.cur_service)
    temp.set_vexpand(True)
    temp.set_hexpand(True)
    contextcont.attach(temp,1,1,1,1)
    self.navcontextmain.show_all()
    

  def genservicecontext(self,_service):
    if _service=="admin":
      adminsc_f=Gtk.Frame()
      adminsc_f.set_label("Admin")
      if self.linkback.main.scn_servers.get_service(self.cur_server,self.cur_domain,"admin") is None:
        adminsc_f.add(Gtk.Label("No permission"))
        adminsc_f.show_all()
        return adminsc_f
      adminsc=Gtk.Grid()
      adminsc.set_row_spacing(2)
      adminsc.set_border_width(2)
      adminsc_f.add(adminsc)
      adminsc_f.show_all()
      return adminsc_f
    elif _service=="special" or \
         _service in self.special_services:
      spsc_f=Gtk.Frame()
      spsc_f.set_label("Specialservice")
      if self.scn_servers.get_service(self.cur_server,self.cur_domain,_service) is None and \
         self.scn_servers.get_service(self.cur_server,self.cur_domain,"special") is None and \
         self.scn_servers.get_service(self.cur_server,self.cur_domain,"admin") is None:
        temp=Gtk.Label("No permission")
        spsc_f.add(temp)
        spsc_f.show_all()
        return spsc_f
      spsc=Gtk.Grid()
      spsc.set_row_spacing(2)
      spsc.set_border_width(2)
      spsc_f.add(spsc)
      addnodebut=Gtk.Button("Add Node")
      spsc.attach(addnodebut,0,0,1,1)
      addservebut=Gtk.Button("Add Service")
      spsc.attach(addservebut,0,1,1,1)
      
      changemessagebut=Gtk.Button()
      if self.cur_domain=="admin":
        changemessagebut.set_text("Change Server Message")
      else:
        changemessagebut.set_text("Change Domain Message")
      spsc.attach(changemessagebut,0,2,1,1)
      #addusertoservice
      spsc_f.show_all()
      return spsc_f
    elif _service=="main":
      mainsc_f=Gtk.Frame()
      mainsc_f.set_label("Main node")
      mainsc=Gtk.Grid()
      mainsc.set_row_spacing(2)
      mainsc.set_border_width(2)
      mainsc_f.add(mainsc)
      return mainsc_f
    elif _service=="notify":
      notifysc_f=Gtk.Frame()
      notifysc_f.set_label("Notify")
      notifysc=Gtk.Grid()
      notifysc.set_row_spacing(2)
      notifysc.set_border_width(2)
      notifysc_f.add(notifysc)
      return notifysc_f
    else:
      defaultsc_f=Gtk.Frame()
      defaultsc_f.set_label("__"+_service)
      defaultsc=Gtk.Grid()
      defaultsc.set_row_spacing(2)
      defaultsc.set_border_width(2)
      defaultsc_f.add(defaultsc)

      return defaultsc_f

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

  def select_domain(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,temp[0][temp[1]][0])

  def goback_domain(self,*args):
    self.update(self.cur_server,self.cur_domain) 
  
  def select_service(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    self.navbar.override_background_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.7, 1, 0.7, 1))
    self.update(self.cur_server,self.cur_domain,temp[0][temp[1]][0])
    
  ### ?? section ###

  def select_context_server(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    tempmessage=self.linkback.main.c_get_server_message(temp[0][temp[1]][0])
    if tempmessage is None or tempmessage=="":
      self.selectedservermessage.set_text("No message")
    else:
      self.selectedservermessage.set_text(tempmessage)

  def select_context_domain(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    tempmessage=self.linkback.main.c_get_domain_message(self.cur_server,temp[0][temp[1]][0])
    if tempmessage is None or tempmessage=="":
      self.selecteddomainmessage.set_text("No message")
    else:
      self.selecteddomainmessage.set_text(tempmessage)

  def select_context_service(self,*args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if len(self.servicef.get_children())>=1:
      self.servicef.get_children()[0].destroy()
    self.servicef.add(self.genservicecontext(temp[0][temp[1]][0]))
    self.servicef.show_all()
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
    dialog = scnServerEditDialog(self.parent,"Add new server","")
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        tempcertname=dialog.certname.get_text()
        if tempcertname=="":
          tempcertname=None
        if self.linkback.main.c_add_server(dialog.servername.get_text(),dialog.url.get_text(),tempcertname)==True:
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
    temp=self.linkback.main.scn_servers.get_server(_server)
    if temp is None:
      self.parent.state_widget.set_text("Not exists")
      return
    #todo: show cert
    dialog = scnServerEditDialog(self.parent,"Edit server",_server,temp)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        tempcertname=dialog.certname.get_text()
        if check_invalid_s(tempcertname)==False or check_invalid_s(dialog.servername.get_text())==False:
          printerror("Invalid characters")
          return False
        if tempcertname!="" and tempcertname!=temp[2]:
          if dialog.certchange.get_active()==False:
            if self.linkback.main.scn_servers.update_cert_name(_server,tempcertname)==False:
              return False
          else:
            if self.linkback.main.scn_servers.change_cert(_server,tempcertname)==False:
              return False
        if dialog.servername!=_server:
          self.linkback.main.scn_servers.update_server_name(_server,dialog.servername.get_text())
          
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

  def register_domain(self,*args):
    dialog = scnNameAddDialog(self.parent,"Register",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_register_domain(self.cur_server,dialog.name.get_text())==True:
          self.updatedomainlist()
          self.parent.state_widget.set_text("Success")
          #returnel=Gtk.Label("Success")
        else:
          self.parent.state_widget.set_text("Error2")
      else:
        self.parent.state_widget.set_text("Error")
    except Exception as e:
      self.parent.state_widget.set_text(str(e))
    dialog.destroy()


  def delete_domain_intern(self,_delete_domain):
    returnstate=False
    dialog = scnDeletionDialog(self.parent,self.cur_server,_delete_domain)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_domain(self.cur_server,_delete_domain)==True:
          self.linkback.main.scn_servers.del_domain(self.cur_server,_delete_domain)
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
      #self.linkback.main.scn_servers.del_domain(self.cur_server,_delete_domain)

    return returnstate

  def delete_domain(self, *args):
    temp=self.navbox.get_selection().get_selected()
    if temp[1] is None:
      return
    if self.delete_domain_intern(temp[0][temp[1]][0])==True:
      self.updatedomainlist()


  def delete_domain2(self, *args):
    if self.delete_domain_intern(self.cur_domain)==True:
      self.update(self.cur_server)
      self.updatedomainlist()
  ### domain/service section ###

  def add_service(self,*args):
    dialog = scnNameAddDialog(self.parent,"Add Service",self.cur_server)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if True==True:#self.linkback.main.c_register_domain(self.cur_server,dialog.domain.get_text())==True:
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
    dialog = scnDeletionDialog(self.parent,self.cur_server,self.cur_domain,_delete_service)
    try:
      if dialog.run()==Gtk.ResponseType.OK:
        if self.linkback.main.c_delete_service(self.cur_server,self.cur_domain,_delete_service)==True:
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
    if self.delete_service_intern(self.cur_domain)==True:
      self.update(self.cur_service)
      self.updateservicelist()



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
