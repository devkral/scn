
from gi.repository import Gtk
import hashlib
import logging


class friendstab(object):
  friendbox=None
  
  def update_friend_list(self,*args):
    temp2=self.scn_servers.list_servers()
    if temp2 is None:
      return False

  def select_friend(self,*args):
    pass

  def __init__(self):
    self.friendbox=self.builder.get_object("friendbox")
    self.update_friend_list()
