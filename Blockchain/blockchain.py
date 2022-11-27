import hashlib
import random

# <------------------- BLOCK 1 ----------------------------------------> 

block = bytes.fromhex('4efc')

#print(block[:1].hex()=='00')
# while(block[:2].hex()!='0000'):
#     nonce = random.randint(5234654, 999999999999)
#     print("Nonce:",nonce)
#     nonceB = (nonce).to_bytes((nonce.bit_length()+7)//8, byteorder='big')

#     quote = 'Thus, programs must be written for people to read, and only incidentally for machines to execute. -- Alan J. Perlis'
#     quoteB = bytes(quote.encode('ascii'))

#     prev_block = bytes.fromhex('4efc421276208cb7c72686f9c42f362a665c3cf00492ffbe41a4c70d1a4930eb');

#     block = hashlib.sha256((prev_block)+nonceB+quoteB).digest()
#     print(block.hex())

# <------------------- BLOCK 2 ----------------------------------------->

# block = bytes.fromhex('	00006247a8acd4294ed62915db9a47abe584d98a19bb6769eeff6f988973da79')
# quote2 = 'It is practically impossible to teach good programming to students that have had a prior exposure to BASIC: as potential programmers they are mentally mutilated beyond hope of regeneration. -- Edsger Dijkstra';
# quote2B = bytes(quote2.encode('ascii'))

# nonce = 100
# nonceB = (nonce).to_bytes((nonce.bit_length()+7)//8, byteorder='big')
# block2 = hashlib.sha256((block)+nonceB+quote2B).digest()
# while(block2[:2].hex()!='0000'):
#     nonce = random.randint(5234654, 999999999999)
#     print("Nonce:",nonce)
#     nonceB = (nonce).to_bytes((nonce.bit_length()+7)//8, byteorder='big')
#     block2 = hashlib.sha256((block)+nonceB+quote2B).digest()

# print(block2.hex())

# <------------------- BLOCK 3 ----------------------------------------->

block2 = bytes.fromhex('00001d610b591ae95e3649976489d2c08c5a6db35ab138b2ac073dffdeedfbe8')
quote3 = "You know you're in love when you can't fall asleep because reality is finally better than your dreams. -- Dr. Seuss";
quote3B = bytes(quote3.encode('ascii'))

nonce = 100
nonceB = (nonce).to_bytes((nonce.bit_length()+7)//8, byteorder='big')
block3 = hashlib.sha256((block2)+nonceB+quote3B).digest()
while(block3[:2].hex()!='0000'):
    nonce = random.randint(5234654, 999999999999)
    print("Nonce:",nonce)
    nonceB = (nonce).to_bytes((nonce.bit_length()+7)//8, byteorder='big')
    block3 = hashlib.sha256((block2)+nonceB+quote3B).digest()

print(block3.hex())
