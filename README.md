#PolyPasswordHasher-ECC

An extension of the [PolyPasswordHasher password storage scheme](https://github.com/PolyPasswordHasher/PolyPasswordHasher). 
This repository uses Reed Solomon error correcting codes instead of vanilla Shamir Secret Sharing to manage a polypasswordhasher store.

More details about the original scheme can be found [here](https://github.com/PolyPasswordHasher/PolyPasswordHasher).
This version enables an error-correcting threshold-cryptosystem by using both errors and erasures decoding. We use the Python library [unireedsolom 1.0](https://pypi.python.org/pypi/unireedsolomon)
for implementing the same. This allows improved performance of the server when validating accounts as some number of incorrect passwords
are allowed for recovery of the secret.

Given the value of the threshold is k and recovery is tried using n accounts, then the number of permissible erroraneous passwords t is
given by the relation:
```
 2*t <= n-k 
```

## Installation/Running

You need to download and extract the unireedsolomon library in the same folder as your files in order to be able to use the functions 
of this repository. We have already included the library in this reference implementation. 
To build and run test files, navigate to the directory containing the files and run
```
$ python testpolypasswordhasher.py
```
or whichever file you want to run

## Tests and Code Examples

***testrs.py***   
To check the encoding/decoding provided by the unireedsolomon library. Encoding appends the message (k bytes) with n-k parity bytes.
RS can correct errors both in the message and the ecc symbols.
You can try different combinations of errors and erasures to understand the conditions for correct decoding.

```python
from unireedsolomon import rs

if __name__ == "__main__":
    
    #the ReedSolomon library object 
    #n is the length of the codeword and k is the threshold
    rsman = rs.RSCoder(255, 5) #RSCoder(n, k)
    
    mes = 'hello'
    
    # Encoding message into codeword
    mesecc = rsman.encode(mes)
    
    ii = 250 #no of erasures
    v = 1 #no of errors
    # ii + 2*v <= n-k to decode correctly
    
    #erasing from codeword
    mesecc2 = "\x00" * ii + mesecc[ii:]
    
    # error one character, the rest is erased
    mesecc3 = "\x00" * (ii-2) + "a" + mesecc[ii-2+v:] 
    
    # maximum 7 errors allowed
    mesecc4 = mesecc[:3] + "abcdefh" + mesecc[10:] 
    
    #we need to provide a list erasure positions to the decode function
    erasures_pos = [i for i in xrange(len(mesecc2)) if mesecc2[i] == "\x00"]
    
    # Correct only using erasures decoding, returns the corrected message and the corrected ecc
    eras_r1, eras_r2 = rsman.decode(mesecc2, erasures_pos=erasures_pos, only_erasures=True)
    # Correct using errors+erasures decoding
    r1, r2 = rsman.decode(mesecc2, erasures_pos=erasures_pos)
    # Correct using errors+erasures decoding with the message containing erasures and one error
    err_r1, err_r2 = rsman.decode(mesecc3, erasures_pos=erasures_pos[:ii-2])
    # Correct using errors+erasures decoding the message containing only errors
    err2_r1, err2_r2 = rsman.decode(mesecc4, erasures_pos=[])

    #check the results
    #prints True or False
    print "Correctly decoded: ", rsman.check(eras_r1 + eras_r2)
    print "Correctly decoded: ", rsman.check(r1 + r2)
    print "Correctly decoded: ", rsman.check(err_r1 + err_r2)
    print "Correctly decoded: ", rsman.check(err2_r1 + err2_r2)

```

***testreedsolomon.py***   
To verify the secret sharing and recovery using the library.
```python
import reedsolomon

#create some shares out of the secret
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

```

***testpolypasswordhasher.py***  
To check the extension of the scheme to actual usernames and passwords. The various functions required can be implemented as follows:
```python
import polypasswordhasher

THRESHOLD = 3
# require knowledge of 3 shares to decode others.   Create a blank, new
# password file...

pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

# make some normal user accounts...
pph.create_account('alice','kitten',1)
pph.create_account('bob','puppy',1)
pph.create_account('charlie','velociraptor',1)
pph.create_account('dennis','menace',1)
pph.create_account('gone','girl',1)
pph.create_account('eve','iamevil',0)


# try some logins and make sure we see what we expect...
assert(pph.is_valid_login('alice','kitten') == True)
assert(pph.is_valid_login('bob','puppy') == True)
assert(pph.is_valid_login('alice','nyancat!') == False)
assert(pph.is_valid_login('dennis','menace') == True)
assert(pph.is_valid_login('dennis','password') == False)


# persist the password file to disk
pph.write_password_data('securepasswords')
 
# If I remove this from memory, I can't use the data on disk to check 
# passwords without a threshold
pph = None

# let's load it back in
pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD,passwordfile = 'securepasswords')

# The password information is essentially useless alone.   You cannot know
# if a password is valid without threshold or more other passwords!!!
try: 
  pph.is_valid_login('alice','kitten')
except ValueError:
  pass
else:
  print "Can't get here!   It's still bootstrapping!!!"

# is able to handle one correct incorrect password out of five when threshold is three
pph.unlock_password_data([('alice','kitten'),('bob','puppy'),('gone','boy'),('charlie','velociraptor'),('dennis','menace')])

# now, I can do the usual operations with it...
assert(pph.is_valid_login('alice','kitten') == True)

pph.create_account('moe','tadpole',1)
pph.create_account('larry','fish',0)

## test isolated validation

pph = None

# let's load it back in
pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD,
		passwordfile = 'securepasswords', isolated_check_bits=2)

# create a bootstrap account
pph.create_account("bootstrapper", 'password', 0)
try:
  assert(pph.is_valid_login("bootstrapper",'password') == True)
  assert(pph.is_valid_login("bootstrapper",'nopassword') == False)
except ValueError:
  print("Bootstrap account creation failed.")

# The password threshold info should be useful now...
try: 
  assert(pph.is_valid_login('alice','kitten') == True)
  assert(pph.is_valid_login('admin','correct horse') == True)
  assert(pph.is_valid_login('alice','nyancat!') == False)
except ValueError:
  print "Isolated validation but it is still bootstrapping!!!"

try:
  pph.create_account('moe','tadpole',1)
except ValueError:
  # Should be bootstrapping...
  pass
else:
  print "Isolated validation does not allow account creation!"

# with a threshold+2 number of correct passwords, and one error, it decodes and is usable.
pph.unlock_password_data([('admin','correct horse'), ('root','battery staple'), ('bob','puppy'),('alice','nyancat!'),('dennis','menace')])

# now, I can do the usual operations with it...
assert(pph.is_valid_login('alice','kitten') == True)

# including create accounts...
pph.create_account('moe','tadpole',1)
pph.create_account('larry','fish',0)

```
