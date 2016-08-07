
'''
 Filename: shift_cipher.py - Ceasar and affine shift cipher.

 note: using 100 char ring (a-zA-Z0-9 and some special chars)

 Encrypt: given plain txt msg, calc cipher result
 Decrypt: given cipher msg, calc plain text result

   Ceasar shift cipher:
     Encrypt :  (pt_msg + key) mod N = ct_res
     Decrypt :  (ct_msg - key) mod N = pt_res    (inverse)

   Affine shift cipher:
     Encrypt :  ((pt_msg * key1) + key2) mod N = ct_res
     Decrypt :  ((ct_msg - key2) * key^-1) mod N = pt_res
------------------------------------------------------------------------------
 Notes:
 - In the shift cipher, 'mod' is used to keep the result within the
   legal ring values. For example, if the legal values where a-z, 
   that would be 26 values, so modulo 26 would be applied after applying
   the key. This would ensure the result will remain within the 'ring' 
   of legal values.

 - The chr() and ord() would have been used, but the printable char's ascii 
   value could be non-contiguous as we include more chars later; the 'mod' 
   would not work. So, it would be better to add a lookup table with chars and 
   values. The values are contiguous so that the 'mod' will wrap to a legal 
   value inside the char space.

 @petergmale

'''
import sys,re,string


def usage():
  print("Usage: {} [func] <key[,key]>  <msg>".format(sys.argv[0]))
  print(" func  : <string>. encode or decode function [enc|dec]")
  print(" key   : <int>.    cipher key(s). If multiple keys, separate by comma.")
  print(" msg   : <string>. text message to convert")
  print(" Single key will perform Ceasar shift enc/dec")
  print(" Multiple keys will perform Affine shift enc/dec")
  

# Neat trick to keep the ring structure. This allows the ring to be
# kind of like a singleton
#
class MetaCipherRing(type):
  """
  ring consists of: printable NON-whitespace + <space> + <tab> 
    The lu is a lookup where each char has a sequential int value.
      re.sub(pattern, repl, string)
      replace 'printable' with '' if matches 'pattern'
      In otherwords, mask out all with '', but NOT '\S+ \t'
      (non-whitespace, space and tab).
    The values for ea key are sequential numbers.
  """
  _chars = re.sub(r'[^\S+ \t]+', '', string.printable)  # Create char ring
  _ms = len(_chars)                                     # mod size of ring
  _lu = {}                                              # lookup dict (char:int)

  # define getter/setter property def's
  def _get_chars(self):
    if len(self._chars) == 0:
      self._chars = re.sub(r'[^\S+ \t]+', '', string.printable)   # Create char ring
    return self._chars

  def _get_ms(self):
    if self._ms == 0:           # only set _ms once
      self._ms = len(self._chars)
    return self._ms

  def _get_lu(self):
    if len(self._lu) == 0:      # only create _lu once; singleton?
      self._lu.update(dict([self._chars[i],i] for i in xrange(self._ms)))
    return self._lu

  chars = property(_get_chars)  # getter, NO setter
  ms = property(_get_ms)        # getter, NO setter
  lu = property(_get_lu)        # getter, NO setter


class CipherRing(object):
  __metaclass__ = MetaCipherRing

  @classmethod
  def get_chr(cls,i):
    return cls.chars[i]

  @classmethod
  def get_ord(cls,c):
    return cls.lu[c]



def disp_output(func,key,msg,res):
  """Display the key,msg,res output"""
  print("func: {}\nkey: {}\nmsg: '{}'\nres: '{}'".format(func,key,msg,res))

def get_args(argv):
  """Get the legal arg values...
              0      1     2           3
    format: <prog> [func] <key[,key]> <msg>
  """
  for i in argv:
    print(i)
     
  if(len(argv) == 3):     # prog <key> <msg>
    func = "dec"
    kp,mp = 1,2           # key and msg positions
  elif(len(argv) == 4):   # prog <key> <func> <msg>
    func = argv[1]
    kp,mp = 2,3           # key and msg positions
  else:
    usage()
    sys.exit(1)

  try:
    k = argv[kp].split(',')   # key list; accept multiple keys
    m = argv[mp]              # msg
    #check_key(k)              # limitations for correct keys
  except ValueError:
    usage()
    sys.exit(1)

  return(func,k,m)  # return the func,key,msg
# get_args

def check_key(key):
  """There are limitations if using multiple keys"""

  if len(key) > 1:
    "//todo:..."
    return(1)
  else:
    return(0)


def calc_cipher_result(func,key,msg):
  """Calculate the cipher result; cipher text or msg"""

  rslt=''   # cipher text result

  try:
    #keys = list(int(key))    # make sure key is a list
    keys = list(key)    # make sure key is a list

    for c in list(msg): # each char in msg

      if len(keys) > 1:
        if func.lower() == "enc":
          # affine Encode
          rslt += CipherRing.get_chr((CipherRing.get_ord(c) + int(keys[0])) % CipherRing.ms)
        else:
          # affine Decode
          rslt += CipherRing.get_chr((CipherRing.get_ord(c) - int(keys[0])) % CipherRing.ms)
      else:
        if func.lower() == "enc":
          # ceasar Encode
          rslt += CipherRing.get_chr((CipherRing.get_ord(c) + int(keys[0])) % CipherRing.ms)
        else:
          # ceasar Decode
          rslt += CipherRing.get_chr((CipherRing.get_ord(c) - int(keys[0])) % CipherRing.ms)

  except:
    print("Error calculating enc/dec values")
    usage()
    sys.exit(1)

  return rslt


#-------------------------
def main():

  try:
    func1,key,msg1 = get_args(sys.argv)
  except: 
    print("Invalid get_args() ")
    sys.exit(1)


  # gen cipher text (or msg if decode)
  rslt1 = calc_cipher_result(func1,key,msg1)
  disp_output(func1,key,msg1,rslt1)

  # invert func
  msg2 = rslt1
  func2 = "dec" if func1 == "enc" else "enc"

  # gen cipher text (or msg if decode)
  rslt2 = calc_cipher_result(func2,key,msg2)
  disp_output(func2,key,msg2,rslt2)

  # confirm we enc/dec correctly
  assert rslt2 == msg1

  return



if __name__ == "__main__":
    main()
