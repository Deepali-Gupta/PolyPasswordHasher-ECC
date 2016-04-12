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
To check the encoding/decoding provided by the unireedsolomon library.

***testreedsolomon.py***   
To verify the secret sharing and recovery using the library.

***testpolypasswordhasher.py***  
To check the application of the scheme to usernames and passwords.


