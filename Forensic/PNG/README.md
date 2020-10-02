# Fword CTF | NULL [479 pts]

**Category:** Forensics
**Solves:** 45

## Description
>Recover it!
<br><br>
Author: _**KOOLI**_

## Solution

Based on static analysis of `null.png` image, found out that there's a problem with IHDR integrity

```bash
$ pchunk_info NULL.png 
Filename: NULL.png
Size: 19617

Chunk Info
Id   Type Offset    Size         Data Length CRC                           
0    IHDR 0xc       13           13          e3677ec0 (Must be 3b8b7c12)   
1    iCCP 0x25      388          388         e2e70845                      
2    bKGD 0x1b5     6            6           a0bda793                      
3    pHYs 0x1c7     9            9           78a53f76                      
4    tIME 0x1dc     7            7           3f1931e1                      
5    tEXt 0x1ef     25           25          57810e17                      
6    IDAT 0x214     8192         8192        b20470cd                      
7    IDAT 0x2220    8192         8192        75ddaff8                      
8    IDAT 0x422c    2656         2656        bebdfa97                      
9    IEND 0x4c98    0            0           ae426082                      

$ file NULL.png  
NULL.png: PNG image data, 0 x 0, 8-bit/color RGBA, non-interlaced

```

We assumed that the `checksum` was fine, so it must be the `data` itself (spotted on `0 x 0` pixels size)

<br>

**Size Calculation**

Assumed that IDAT was fine, then using `python-z3` we can estimate the image `width` & `height`.

``` bash
$ pchunk_info NULL.png -t IDAT -e
Extracted 3 chunks


$ python3

>>> from zlib import decompress
>>> 
>>> base = 'chunks_NULL'
>>> 
>>> def read_file(name):
...     path = '%s/%s-IDAT' % (base, name)
...     with open(path, 'rb') as c:
...         return c.read()[8:-4]
... 
>>> idat = [read_file(_) for _ in range(6,9)]
>>> data = decompress(b''.join(idat))
>>> 
>>> print(len(data))
1155777
```

``` bash
$ python3 

>>> from z3 import *
>>>
>>> h = Int('h')
>>> w = Int('w')
>>>
>>> s = Solver()
>>> s.add(h + 4*h*w == len(data))
>>> s.add(w > 0, w < 1000)
>>> s.add(h > 0, h < 1000)

>>> while s.check() == sat:
...  print(s.model())
...  s.add(Or(h != s.model()[h], w != s.model()[w]))

[w = 878, h = 329]
```

<br>

**Applying changes**

For the last step, we can change `size` value directly from `IHDR` chunk

```python
import struct

def l2b(n):
    return struct.pack('!I', n)

png = open('NULL.png', 'rb').read()
start = png[:0x010]
last = png[0x018:]
data = b''.join(map(l2b, [878, 329]))

open('flag.png', 'wb').write(start + data + last)

```

```bash
$ python3 sv.py

$ pchunk_info flag.png           
Filename: flag.png
Size: 19617

Chunk Info
Id   Type Offset    Size         Data Length CRC                           
0    IHDR 0xc       13           13          e3677ec0                      
1    iCCP 0x25      388          388         e2e70845                      
2    bKGD 0x1b5     6            6           a0bda793                      
3    pHYs 0x1c7     9            9           78a53f76                      
4    tIME 0x1dc     7            7           3f1931e1                      
5    tEXt 0x1ef     25           25          57810e17                      
6    IDAT 0x214     8192         8192        b20470cd                      
7    IDAT 0x2220    8192         8192        75ddaff8                      
8    IDAT 0x422c    2656         2656        bebdfa97                      
9    IEND 0x4c98    0            0           ae426082  
```

### Flag

[](flag.png)

**FwordCTF{crc32_is_the_way}**