
import threading
import time

class rwlock(object):
  readlock=None
  writelock=None
  _writes_passed=0
  def __init__(self):
    self.readlock=threading.Semaphore(1)
    self.writelock=threading.Event()
    self.writelock.clear()
  

  def readaccess(self,func):
    def tfunc(*args,**kwargs):
      try:
        self.readlock.acquire(False)
        self.writelock.wait()
        func(*args,**kwargs)
      except Exception:
        pass
      finally:
        self.readlock.release()
    return tfunc


  def writeaccess(self,func):
    def tfunc(*args,**kwargs):
      time.sleep(1)
      try:
        self.writelock.set()
        self.readlock.acquire(True)
        self._writes_passed+=1
        func(*args,**kwargs)
      except Exception:
        pass
      finally:
        self._writes_passed-=1
        self.readlock.release()
        if self._writes_passed==0:
          self.writelock.clear()
    return tfunc
