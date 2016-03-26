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
