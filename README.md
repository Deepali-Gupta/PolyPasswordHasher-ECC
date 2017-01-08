#PolyPasswordHasher-ECC

An extension of the [PolyPasswordHasher password storage scheme](https://github.com/PolyPasswordHasher/PolyPasswordHasher). 
This repository uses Reed Solomon error correcting codes instead of vanilla Shamir Secret Sharing to manage a polypasswordhasher store.

More details about the original scheme can be found [here](https://github.com/PolyPasswordHasher/PolyPasswordHasher).
This version enables an error-correcting threshold-cryptosystem by using both errors and erasures decoding with [unireedsolom 1.0](https://pypi.python.org/pypi/unireedsolomon). This provides better performance for the server when validating accounts as some number of incorrect passwords are allowed for successful secret recovery. Adding to this, the life of the attacker is also harder, because this scheme exerts more effort at higher error rates.

Given the value of the threshold is k and recovery is tried using n accounts, then the number of permissible erroraneous passwords t is
given by the relation:
``
 2*t <= n-k 
``

## Code Example

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
assert(pph.is_valid_login('dennis','password') == False)

# persist the password file to disk
pph.write_password_data('securepasswords')
 
# If I remove this from memory, I can't use the data on disk to check 
# passwords without a threshold
pph = None

# let's load it back in
pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD,passwordfile = 'securepasswords')

# The password information is essentially useless alone.   You cannot know
# if a password is valid without recovery using threshold or more other passwords!!!

# is able to handle one correct incorrect password out of five when threshold is three
pph.unlock_password_data([('alice','kitten'),('bob','puppy'),('gone','boy'),('charlie','velociraptor'),('dennis','menace')])

# now, I can do the usual operations with it...

##for testing isolated validation

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

# the rest of the recovery and usage works same as before

```
