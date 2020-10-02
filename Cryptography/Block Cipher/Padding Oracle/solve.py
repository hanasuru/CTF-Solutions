from pwn import *


r = remote("192.168.3.100", 6978)

awal = r.sendline("")
awal_enc  = r.recvline()[:-1]

# for i in range(1, 17):
#   payload = "A"*i
#   r.sendline(payload)
#   tes = r.recvline()[:-1]
#   if len(tes) != len(awal_enc):
#     pad_awal = i
#     break


# p_cek = "A"*pad_awal + "A"*32
# r.sendline(p_cek)
target_block = False
pok = ""
for cok in range(1,48):
  tes = "A"*cok
  r.sendline(tes)
  ceks = r.recvline()[:-1]
  ceks = [ceks[i:i+32] for i in range(0,len(ceks),32)]

  for j in range(0, len(ceks)-1):
    if ceks[j] == ceks[j+1]:
      target_block = j + 2
      for pol in ceks:
        print pol
      break
  if target_block:
    break

print cok
gege = "A"*cok + "B"*16 + "B"*16
r.sendline(gege)  
ceks = r.recvline()[:-1]
ceks = [ceks[i:i+32] for i in range(0,len(ceks),32)]
print "==========="
for pol in ceks:
  print pol






wew = 15
simpan = ""
for loop in range(16):
  print  "LOOP {}".format(loop)
  for i in range(0x20,0x7f):
    pload = "A"*cok + "A"*wew + simpan + chr(i) + "A"*wew
    r.sendline(pload)
    rec = r.recvline()[:-1]
    rec = [rec[j:j+32] for j in range(0,len(rec),32)]
    if rec[target_block] == rec[target_block+1]:
      print "Dapat ", chr(i)
      simpan = simpan + chr(i)
      print simpan
      wew -= 1
      break

# known = "KKSI2019{MERDEKA"
known = simpan
wew = 15
cuk = 1
simpan = ""
for loop in range(16):
  print  "LOOP {}".format(loop)
  if "}" in simpan:
    break
  for i in range(0x20,0x7f):
    pload = "A"*cok + known[cuk:] + simpan + chr(i)  +"A"*wew
    r.sendline(pload)
    rec = r.recvline()[:-1]
    rec = [rec[j:j+32] for j in range(0,len(rec),32)]
    if rec[target_block] == rec[target_block+2]:
      print "Dapat ", chr(i)
      simpan = simpan + chr(i)
      print simpan
      cuk += 1
      wew -= 1
      break

print known + simpan
