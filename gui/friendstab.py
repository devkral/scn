
from gi.repository import Gtk
import hashlib
import logging

def create_list_entry(name):
  ret=Gtk.ListBoxRow()
  grid=Gtk.Grid()
  ret.add(grid)
  grid.attach(Gtk.Label(name),0,0,1,1)
  Gtk.Button()
  return ret

class friendstab(object):
  friendslist=[]
  #friendslist=[]
  
  def __init__(self):
    pass
