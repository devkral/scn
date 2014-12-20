
from gi.repository import Gtk

class scnDeletionDialog(Gtk.Dialog):
  def __init__(self, _parent, _server,_domain=None,_channel=None, _node=None):
    Gtk.Dialog.__init__(self, "Confirm Deletion", _parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    if _domain is not None and _channel is not None and _node is not None:
      label=Gtk.Label("Shall node \""+_node+"\" in "+_channel+"/"+_server+"/"+_domain+" be deleted?")
    elif _domain is not None and _channel is not None:
      label=Gtk.Label("Shall channel \""+_channel+"\" of "+_server+"/"+_domain+" be deleted?")
    elif _domain is not None and _channel is None:
      label=Gtk.Label("Shall domain \""+_domain+"\" on "+_server+" be deleted?")
    else:
      label=Gtk.Label("Shall server \""+_server+"\" be deleted?")

    box = self.get_content_area()
    box.add(label)
    self.show_all()

class scnSelfDeletionDialog(Gtk.Dialog):
  def __init__(self, _parent, _server,_domain,_channel):
    Gtk.Dialog.__init__(self, "Confirm Deletion", _parent,
                        Gtk.DialogFlags.MODAL|Gtk.DialogFlags.DESTROY_WITH_PARENT)
    self.set_default_size(150, 100)
    self.add_button("Cancel", Gtk.ResponseType.CANCEL)
    self.add_button("OK", Gtk.ResponseType.OK)
    label=Gtk.Label("Shall your serve in "+_channel+"/"+_server+"/"+_domain+" be deleted?")
    
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
    tcn=Gtk.Label("Server Certificate name \nDefault: Servername: ")
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


class scnAddFriendDialog(Gtk.Dialog):
  name=None
  def __init__(self, _parent, _title,_server,_domain,_nodename):
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
    message=Gtk.Label("Add {}/{} as:".format(_server,_domain))
    self.name=_nodename
    cont.attach(message,0,0,1,1)
    cont.attach(self.name,0,1,1,1)

    self.show_all()
