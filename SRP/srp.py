import hashlib

a = 29
g = 5
p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407
publicKey = g**a%p
print("public key value: ",publicKey)

pas = 'outsheathe'
password = bytes(pas.encode('ascii'))
print(password)

#salt = int('0xf7dcbfdb',base=16)
#val = salt.to_bytes(salt.bit_length(), 'big')
salt = bytes.fromhex("f119ea19")
print(salt)

val = salt+password
print(val)

digest = hashlib.sha256(val).digest()

for x in range(0, 999):
    digest = hashlib.sha256(digest).digest()
print("x value: ",digest)

g = 5
gg = (g).to_bytes((g.bit_length() + 7) // 8, byteorder='big')
pp = (p).to_bytes((p.bit_length() + 7) // 8, byteorder='big')
# print("gg value: ", gg)
# print("pp value: ", pp)
pg = pp+gg
k = hashlib.sha256(pg).digest()
print("k value: ", k)

g = 5
#g = bytes(5)
#p = bytes(233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407)
B = 31247658607463884853009663922845756352137075941804405568296006708786793407366663402735920517645575036515566060105633853428086176036119495665372059095968824367175574172893769043137428041767305957670633757970812848391896905843098778107240045435480382179851645486482501596278040527039515472239191854164524172080
k = int.from_bytes(k, "big")
print("k integer value: ", k)
gg = int.from_bytes(gg, "big") 
pp = int.from_bytes(pp,"big")
digest = int.from_bytes(digest, "big")
print("x integer value: ", digest)
print("g input value: ",gg)
print("p input value: ",pp)

def fast_mod_exp(b, exp, m):
    res = 1
    while exp > 1:
        if exp & 1:
            res = (res * b) % m
        b = b ** 2 % m
        exp >>= 1
    return (b * res) % m

v = fast_mod_exp(g,digest,pp)
res = k*v%pp
print("result: ", res)
print("B value: ",B)
publicKeyDH = B-res
print("Public key DH: ",publicKeyDH)

ga = 186264514923095703125
gaa = ga.to_bytes((ga.bit_length()+7)//8 , byteorder='big')
gb =  publicKeyDH.to_bytes((publicKeyDH.bit_length()+7)//8, byteorder='big')
gab = gaa+gb
u = hashlib.sha256(gab).digest()
u = int.from_bytes(u, "big")
print("u integer value: ", u)



# calculating shared key
power = a+u*digest
#print("power value: ", power)
#sharedKey = publicKeyDH**power
res = fast_mod_exp(publicKeyDH, power, p)

print("Shared key: ",res)




