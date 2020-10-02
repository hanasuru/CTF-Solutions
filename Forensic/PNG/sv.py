import struct

def l2b(n):
    return struct.pack('!I', n)

png = open('NULL.png', 'rb').read()
start = png[:0x010]
last = png[0x018:]
data = b''.join(map(l2b, [878, 329]))

open('flag.png', 'wb').write(start + data + last)
