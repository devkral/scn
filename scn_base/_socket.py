
import sys
import threading
import logging

import socket
import struct
from OpenSSL import SSL

from scn_base._base import sepm,sepc,_check_invalid_chars_base
from scn_base._base import scnNoByteseq,scnReceiveError,scnRejectException
from scn_config import buffersize,max_cmd_size,protcount_max

import random
ra=random.SystemRandom()

#time limiting function
def lt_load(timelimit=2):
  def tfunc (func):
    def tfunc1(*args,**kwargs):
      # thanks to Aaron Swartz
      class stateThread(threading.Thread):
        def __init__(self):
          threading.Thread.__init__(self)
          self.result = None
          self.error = None
          self.daemon = False
          
        def run(self):
          try:
            self.result = func(*args, **kwargs)
          except:
            self.error = sys.exc_info()[0]
      __proc=stateThread()
      __proc.start()
      __proc.join(timelimit)
      if __proc.is_alive()==True:
        __proc.exit()
        raise (TimeoutError)
      if __proc.error is not None:
        raise (__proc.error)
      return __proc.result
    return tfunc1
  return tfunc


class scn_socket(object):
  _buffer=""
  is_end_state=False
  #_socket=None
  #is_end_state=False

  def __init__(self,_socket):
    self._socket=_socket

  #@ltfunc(10)
  def _receive(self,_size):
    return self._socket.recv(_size)
  

  def decode_command(self,minlength,maxlength):
    temp=self._buffer.split(sepc,1)
    if len(temp)==1 and len(temp[0])>=1 and temp[0][-1]==sepm:
      self.is_end_state=True
      self._buffer=""
      if len(temp[0][:-1])<minlength:
        raise(scnReceiveError("decode_command: Too short"))
      if len(temp[0][:-1])>maxlength:
        raise(scnReceiveError("decode_command: Too long"))
      if _check_invalid_chars_base.search(temp[0][:-1]) is not None:
        raise(scnReceiveError("decode_command: Contains invalid characters"))
      return temp[0][:-1]

    if len(temp)>1:
      self._buffer=temp[1]
    else:
      self._buffer=""
    if len(temp[0])<minlength:
      raise(scnReceiveError("decode_command: Too short"))
    if len(temp[0])>maxlength:
      raise(scnReceiveError("decode_command: Too long"))
    if _check_invalid_chars_base.search(temp[0][:-1]) is not None:
      raise(scnReceiveError("decode_command: Contains invalid characters"))
    return temp[0]
  
  def load_socket(self):
    temp=None
    try:
      #cleanup invalid data
      for protcount in range(0,protcount_max):
        temp1=self._receive(buffersize)
        tmp_scn_format=struct.Struct(">"+str(len(temp1))+"s")
        #cleanup invalid chars
        temp=tmp_scn_format.unpack(temp1)[0].decode("utf-8").replace("\n","").replace("\0","")
        #if nothing is left continue cleaning up
        if temp!="":
          break
    except (BrokenPipeError,SSL.ZeroReturnError):
      raise(BrokenPipeError())
    except (SSL.SysCallError) as e:
      if e.args[0]==104 or e.args[0]==-1:
        #"104: ECONNRESET, -1: Unexpected EOF"
        raise(BrokenPipeError())
      else:
        raise(e)
    except (socket.timeout, SSL.WantReadError):
      logging.debug("Command: Timeout or SSL.WantReadError")
    #except (socket.ECONNRESET, socket.EPIPE):
    #  pass
      temp=None
    except Exception as e:
      logging.error("Command: Unknown error while receiving")
      logging.error(e)
      temp=None
    return temp

  def is_end(self):
    return self.is_end_state
  
  # 1 arg: set maxlength, 2 args: set minlength, maxlength
  def receive_one(self,minlength=max_cmd_size,maxlength=None):
    self.is_end_state=False
    if maxlength is None:
      maxlength=minlength
      minlength=0
    if maxlength>buffersize-1:
      logging.debug("Receiving command longer than buffersize-1 is dangerous: use send_bytes and receive_bytes instead")
    if len(self._buffer)>1 and (self._buffer[-1]==sepm or self._buffer[-1]==sepc):
      return self.decode_command(minlength,maxlength)
    elif self._buffer==sepm or self._buffer==sepc:
      temp2=self.load_socket()
      if temp2 is None:
        raise(scnReceiveError("loading from socket failed"))
      self._buffer=temp2
      return self.decode_command(minlength,maxlength)
    else:
      temp2=self.load_socket()
      if temp2 is None:
        raise(scnReceiveError("loading from socket failed"))
      self._buffer+=temp2
      return self.decode_command(minlength,maxlength)

  
  #if no max size is specified, take _minsize as min max
  def receive_bytes(self,min_size,max_size=None):
    if self.receive_one()!="bytes":
      raise(scnNoByteseq("No \"bytes\" keyword"))
    try:
      _request_size=int(self.receive_one())
    except Exception as e:
      logging.error("Bytesequence: Conversion into len (Int) failed")
      logging.error(e)
      self.send("error"+sepc+"int conversion"+sepm)
      raise(scnNoByteseq("int convert"))
    if max_size is None and _request_size==min_size+1: #for sepc/sepm
      self.send("success"+sepm)
    elif min_size<=_request_size and _request_size<=max_size+1: #for sepc/sepm
      self.send("success"+sepm)
    else:
      logging.debug(str(min_size)+","+str(max_size)+" ("+str(_request_size)+")")
      self.send("error"+sepc+"wrong size"+sepm)
      raise(scnNoByteseq("size"))
    scn_format2=struct.Struct(">"+str(_request_size)+"s")
    temp=b""
    remaining=_request_size+buffersize-(_request_size%buffersize) #load also padding
    while True:
      if remaining-buffersize>0:
        temp+=self._receive(buffersize)
        remaining-=buffersize
      else:
        temp+=self._receive(remaining)
        break
    temp=bytes(scn_format2.unpack(temp[0:_request_size])[0])
    #[-1:] because of strange python behaviour.
    #it converts [-1] to int
    if temp[-1:]==bytes(sepm,"utf8"):
      self.is_end_state=True
    elif temp[-1:]==bytes(sepc,"utf8"):
      self.is_end_state=False
    else:
      self.send("error"+sepc+"wrong termination"+sepm)
      raise(scnNoByteseq("termination"))
    return temp[0:-1]

  def send(self,_string):
    temp=bytes(_string,"utf-8")
    tmp_scn_format=struct.Struct(">"+str(len(temp))+"s"+str(ra.randint(0,buffersize-(len(temp)%(buffersize+1))))+"x") # zero padding if buffersize is filled, not an additional packet
    temp=tmp_scn_format.pack(temp)
    self._socket.sendall(temp)

  def send_bytes(self,_byteseq,end=False):
    if end==True:
      _byteseq+=bytes(sepm,"utf8")
    else:
      _byteseq+=bytes(sepc,"utf8")
    len_byte_seq=len(_byteseq) # is same as packed except with padding
    tmp_scn_format=struct.Struct(">"+str(len_byte_seq)+"s"+str(ra.randint(0,buffersize-(len_byte_seq%(buffersize+1))))+"x") # zero padding if buffersize is filled, not an additional packet
    _byteseqpack=tmp_scn_format.pack(_byteseq)
    
    try:
      self.send("bytes"+sepc+str(len_byte_seq)+sepc)
      is_accepting=self.receive_one()
      if is_accepting=="success":
        self._socket.sendall(_byteseqpack)
      else:
        reject_reason=is_accepting
        for protcount in range(0,protcount_max):
          if self.is_end()==True:
            break
          reject_reason+=","+self.receive_one()
        raise(scnRejectException("reject:"+reject_reason))
    except BrokenPipeError as e:
      logging.debug("Bytesequence: BrokenPipe")
      raise(e)
  def close(self):
    self._socket.shutdown()
