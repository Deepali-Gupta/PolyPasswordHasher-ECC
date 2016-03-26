from unireedsolomon import rs

if __name__ == "__main__":
    # Encoding message
    rsman = rs.RSCoder(255, 5) #RSCoder(n, k)
    mes = 'hello'
    mesecc = rsman.encode(mes)
    print("Encoded message:")
    print(mesecc)
    
    ii = 250 #erasure
    v = 0 #errors
    # ii + 2*v <= n-k to decode correctly
    mesecc2 = "\x00" * ii + mesecc[ii:]
    print mesecc2
    mesecc3 = "\x00" * (ii) + "" + mesecc[ii+v:] # error three characters, the rest is erased
    print mesecc3
    mesecc4 = mesecc[:3] + "abcdefh" + mesecc[10:] # maximum 7 errors allowed
    print mesecc4
    erasures_pos = [i for i in xrange(len(mesecc2)) if mesecc2[i] == "\x00"]
    
    # Correct only using erasures decoding
    eras_r1, eras_r2 = rsman.decode(mesecc2, erasures_pos=erasures_pos, only_erasures=True)
    # Correct using errors+erasures decoding
    r1, r2 = rsman.decode(mesecc2, erasures_pos=erasures_pos)
    # Correct using errors+erasures decoding the message containing erasures and one error
    err_r1, err_r2 = rsman.decode(mesecc3, erasures_pos=erasures_pos[:(-1)*v])
    # Correct using errors+erasures decoding the message containing only errors
    err2_r1, err2_r2 = rsman.decode(mesecc4, erasures_pos=[])

    # Print results
    print("-------")
    print("Erasures decoding:")
    print("Decoded message: ", eras_r1, eras_r2)
    print "Correctly decoded: ", rsman.check(eras_r1 + eras_r2)
    print("-------")
    print("Errors+Erasures decoding for the message with only erasures:")
    print("Decoded message: ", r1, r2)
    print "Correctly decoded: ", rsman.check(r1 + r2)
    print("-------")
    print("Errors+Erasures decoding for the message with erasures and one error:")	    
    print("Decoded message: ", err_r1, err_r2)
    print "Correctly decoded: ", rsman.check(err_r1 + err_r2)
    print("Errors+Erasures decoding for the message with multiple errors:")
    print("Decoded message: ",err2_r1, err2_r2)
    print "Correctly decoded: ",rsman.check(err2_r1 + err2_r2)
