"""
Author:
   Justin Cappos  
   Deepali Gupta

Start Date: 11 March 2013
       
Purpose:
  This is a version of Reed Solomon Encoding that is:

  1) built expressly to have the APIs I need
  
  2) definitely not performance tuned. (It's geared for readability.)

  This is just a proof-of-concept!!!
  
  To be used as a library for a project I'm calling PolyPasswordHasherECC.


Example:
	import reedsolomon

	#  Basic tests for this module.

	s = reedsolomon.ReedSolomon(2,'hellothisstringis32byteslongbbye')
	a=s.compute_share(1)
	b=s.compute_share(2)
	c=s.compute_share(3)
	d=s.compute_share(4)
	e=s.compute_share(5)
	f=s.compute_share(6)


	# should be able to recover from any two...
	t = reedsolomon.ReedSolomon(2)


	t.recover_secretdata([b,f]) # output correct secret

	# d should be okay...
	assert(t.is_valid_share(d))

	# corrupt a share
	d=(2,e[1])

	# but not now...
	assert(t.is_valid_share(d) is False)
	secret = reedsolomon.ReedSolomon(2)
	# should be able to recover with one error
	secret.recover_secretdata([a,d,e,f])

	# but not now
	newsecret = reedsolomon.ReedSolomon(2)
	newsecret.recover_secretdata([a,d]) #output incorrect secret

"""
import os
import itertools

__author__ = 'Justin Cappos (jcappos@poly.edu)'
__version__ = '0.1'
__license__ = 'MIT'
__all__ = ['ShamirSecret']

from unireedsolomon import rs

class ReedSolomon(object):
  """ This uses Berleykamp algorithm operations in an incremental way that
  is useful for PolyPasswordHasher.  It encodes the secret into codewords using Reed Solomon errors-and-erasures coding.
  These codewords are then used to create separate shares. It allows checking membership, generating
  shares one at a time, etc.   """

  def __init__(self, threshold, secretdata=None):
    """Creates an object.   One must provide the threshold.   If you want
       to have it create the shares, etc. call it with secret data"""
    self.threshold=threshold
   
    ## the pieces into which the secret is going to be divided
    self.shares = None
    
    self.secretdata=secretdata   
    
    if secretdata is not None:

      ##we need 255 pieces with a threshold of the provided value
      rsman = rs.RSCoder(255,self.threshold)
      
      #list of each secret byte encoded as a codeword
      encoded_bytes = []

      for byte in self.secretdata:
		  
		  byte = rsman.encode(byte)
		  encoded_bytes.append(byte)
      
      share_list = []
      
      #our shares would be 32 bytes long as the encoded_bytes size is 32
     
      #create shares using corresponding bytes from each codeword
      for i in range(self.threshold,255):
		  share = ""		  
		  for byte in encoded_bytes:
			  share=share+byte[i] 
		  share_list.append(share)	  
	    
      self.shares = share_list   
      
      if self.shares is None:
		  raise ValueError("Could not encode correctly")
		  
	  #try recovering the secret from these shares
      recover_list = []
      i = 1
      for share in share_list:
		  recover = (i,share)
		  recover_list.append(recover)
		  i=i+1
      self.secretdata = None
      self.recover_secretdata(recover_list)
      self.secretdata = secretdata
      

  def is_valid_share(self, share):
    """ This validates that a share is correct given the secret data.
        It returns True if it is valid, False if it is not, and raises
        various errors when given bad data.
        """

    # the share is of the format x, share_value
    if type(share) is not tuple:
      raise TypeError("Share is of incorrect type: "+str(type(share)))

    if len(share) !=2:
      raise ValueError("Share is of incorrect length: "+str(share))

    
    if self.shares is None:
      raise ValueError("Must construct shares out of secret before checking is_valid_share")
       
    x, share_value = share

    # let's just compute the right value
    correctshare = bytearray(self.compute_share(x)[1])
    
    if correctshare == share_value:
	  return True
    else:
      return False
    
    
  def compute_share(self, x):
    """ This computes a share, given x.   It returns a tuple with x and the
        individual piece of the secret corresponding to each share... bytes for each byte of the secret.
        This raises various errors when given bad data.
        """

    if type(x) is not int:
      raise TypeError("In compute_share, x is of incorrect type: "+str(type(x)))

    if x<=0 or x>=256:
      raise ValueError("In compute_share, x must be between 1 and 256, not: "+
              str(x))

    if self.shares is None:
      raise ValueError("Must split secret into shares before computing a share")
            
    share_values = None
    
    # Assign the corresponding share_values to the sharenumber
    i = 1
    for  share in self.shares:
		if i == x:
			share_values = share
		i+=1
    
    return (x,share_values)
	

  def recover_secretdata(self, shares):
    """ This recovers the secret data and piecess given at least threshold
        correct shares.   Otherwise, an error is 
        raised."""
    
    # discard duplicate shares
    newshares = []
    for share in shares:
      if share not in newshares:
        newshares.append(share)
    shares = newshares
    
    if self.threshold > len(shares):
      raise ValueError("Threshold:"+str(self.threshold)+
        " is smaller than the number of unique shares:"+str(len(shares))+".")

    if self.secretdata is not None:
      raise ValueError("Recovering secretdata when some is stored. Use check_share instead.")

    # the first byte of each share is the 'x'.
    xs = []
    for share in shares:
      # the first byte should be unique...
      if share[0] in xs:
        raise ValueError("Different shares with the same first byte! '"+
                str(share[0])+"'")

      # ...and all should be the same length
      if len(share[1])!=len(shares[0][1]):
        raise ValueError("Shares have different lengths!")

      xs.append(share[0])
    
    #now try to recover the secret with the given shares
    
    #create 32 encoded strings with message length 0 and codeword length 255
    rsman = rs.RSCoder(255,self.threshold)
    
    #creating a list of the available share numbers
   
    sharelist = []
    for share in shares:
		sharelist.append(share[1])
       
    #now we create the erasure strings, using the share bytes whenever share[0] is in share_numbers, \x00 otherwise
    erasure_strings = []
    for i in range(0,32):
		erasure = "\x00" * 255
		erasure_strings.append(erasure)
    
    for share in shares:
		for i in range(0,32):
			erasure_strings[i] = erasure_strings[i][:share[0]+self.threshold-1] + (share[1][i]) + erasure_strings[i][share[0]+self.threshold:]
     
	#now recover each byte of secret from each erasure_string
    secret = ""
    j = 1
    for erasures in erasure_strings:
		erasures_pos = [i for i in xrange(len(erasures)) if erasures[i] == "\x00"]
		
		secret+=rsman.decode(erasures, erasures_pos = erasures_pos)[0]
		j=j+1
    
    # construct shares again
    self.secretdata = secret
    encoded_bytes = []
    for byte in self.secretdata:
		  
		  byte = rsman.encode(byte)
		  encoded_bytes.append(byte)
      
    share_list = []
      
    for i in range(self.threshold,255):
		share = ""		  
		for byte in encoded_bytes:
			share=share+byte[i] 
		share_list.append(share)	  
	    
    self.shares = share_list

    
   			
####################### END OF MAIN CLASS #######################
