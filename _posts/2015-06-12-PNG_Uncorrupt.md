---
title:      Plaid CTF 2015 - PNG Uncorrupt
author: Giulio "Krishath" De Pasquale
date:       2015-06-12 12:00:00
summary:    This is how you (don't) recover a badly downloaded PNG image.
categories: PlaidCTF2015 Forensics
tags:
 - PlaidCTF
 - Forensics
 - PNG
 - 2015
---

Me and my team, [Tower of Hanoi](https://www.polictf.it), have played the PlaidCTF 2015: while my teammates did reversing stuff, my friend john and I did this awesome forensic challenge.

This was the challenge description:

> We received this PNG file, but we're a bit concerned the transmission may have not quite been perfect.





It was easy to understand we had to repair a PNG file, but first, we checked what we had in our hands. So, we ran `file` on the challenge file:

    corrupt_735acee15fa4f3be8ecd0c6bcf294fd4.png: data

The file was, in fact, corrupted since it wasn't recognized as a PNG image. The next step was to recreate the correct PNG header in our file, which should have been 
`0x89 0x50 0x4E 0x47 0xD 0xA 0x1A 0xA` instead of `0x89 0x50 0x4E 0x47 0x0A 0x1A 0x0A`, the actual header of our challenge's file.

With the help of a hex editor we added the missing `0x0D` byte, renamed the file and...

    solution.png: PNG image data, 960 x 600, 8-bit/color RGB, non-interlaced

Bad news ahead: by opening the image we were greeted by a fantastic *960x600* black image. Not bad. Some of the PNG *chunks* must have been corrupted as well then.

Before going further with the challenge details, I'd like to *quickly* summarize how a PNG file actually is.

A PNG image has a lot of blocks, called *chunks*, which have the same structure: 

    |<- 4 bytes ->| |<- 4 bytes ->| |<- variable ->| |<- 4 bytes  ->|
     |<- LENGTH  ->| |<-   NAME  ->| |<-   DATA   ->| |<- CHECKSUM ->|

The most important one, which actually represents the image, is called **IDAT**.

Now: we made a strong assumption.

**Every chunks' checksum and length section weren't altered at all** (in this way we could understand what was the original content of the data block in each chunk)

With the aforementioned assumption in our mind, we checked if any chunk had an unexpected checksum: `pngcheck` helped us doing this.

There were several corrupted **IDAT** chunks so we wrote a script to bruteforce the missing bytes of each chunk.

What we thought was: the **LENGTH** section indicates how many bytes *should have* been in the chunk in the first place so we compared that value with the *actual* length of the corrupted image **DATA** section.

We wrote the script and... it took a lifetime. No results. Much joy.

When our hope was gone and our PCs were slowly turning in frying pans, [**esseks**](https://github.com/esseks) another awesome teammate, came to the rescue.

> Guys, text conversion.

Which meant: *why would you bruteforce everything?*

When an image is downloaded as *text* through FTP (ASCII Mode), each `0x0D 0x0A` bytes tuple (`\r\n`) is truncated to `0x0A`.

Long story short, here's what we did next:

1. Edited the script making it output the offset in the file where the `0x0D` byte should have been appended
2. Waited for the script to do its magic
3. Edited by hand the PNG image *(sad but true)*

Did we succeed?

![Final Solution](/img/pngcorrupt.png)

PS: I know that some of you was wondering how wonderful our script was...so... have a good headache after it ;-)

{%highlight python%}
import mmap
import struct
from zlib import crc32
import re
import sys
try:
    def strtobytes(x): return bytes(x)
    def bytestostr(x): return str(x)
except (NameError, TypeError):
    strtobytes = str
    bytestostr = str

class IDATChunk:
    counter = ""
    length = ""
    data = ""
    checksum = ""
    def __init__(self, counter, length, data, checksum):
        self.counter = counter
        self.length = int(length.encode("hex"), 16)
        self.data = data
        self.checksum = checksum

def verifyChecksum(data, checksum):
    verify = crc32(strtobytes("IDAT"))
    verify = crc32(data, verify)
    verify &= 2**32 - 1
    verify = struct.pack('!I', verify)
    if verify != checksum:
        return False
    return True


def print_bar(perc=.0):
    SIZE = 20
    return "[%s%s] %f\r" % ("#" * int(20*perc), " " * (20 - int(20*perc)), perc)


def addNewByte(data, seek = "\n", debug=False, byte_to_insert = "\r"):
    if debug:
        print "DEBUG!!!", type(data), data
    indexes = [m.start() for m in re.finditer(seek, data)]
    for i in indexes:
        if byte_to_insert is None:
            for byte_to_insert in range(255):
                new_data = data[:i]+ chr(byte_to_insert) + data[i:]
                yield str(new_data), i, byte_to_insert, len(indexes)
        else:
            new_data = data[:i]+ byte_to_insert + data[i:]
            yield str(new_data), i, byte_to_insert, len(indexes)



def getCorrectData(idatobj):
    if idatobj.length - len(idatobj.data) == 1 :
        for new_data, i, byte_to_insert, num in addNewByte(idatobj.data):
            if verifyChecksum(new_data, idatobj.checksum):
                print "Offset byte: ", str(i), repr(byte_to_insert)
                return new_data

    elif idatobj.length - len(idatobj.data) == 2 :
        counter = 0
        for data_plus_1, i1, byte_1, num in addNewByte(idatobj.data):
            for data_plus_2, i2, byte_2, num2 in addNewByte(data_plus_1):
                sys.stderr.write(print_bar(float(counter)/255/255/num))
                counter += 1
                if verifyChecksum(data_plus_2, idatobj.checksum):
                    print "Offset byte 1: ", str(i1), " Byte: ", repr(byte_1)
                    print "Offset byte 2: ", str(i2), " Byte: ", repr(byte_2)
                    return data_plus_2
    elif idatobj.length - len(idatobj.data) == 3 :
        counter = 0
        for data_plus_1, i1, byte_1, num in addNewByte(idatobj.data):
            for data_plus_2, i2, byte_2, num in addNewByte(data_plus_1):
                for data_plus_3, i3, byte_3, num in addNewByte(data_plus_2):
                    sys.stderr.write(print_bar(float(counter)/255/255/255))
                    counter += 1
                    if verifyChecksum(data_plus_3, idatobj.checksum):
                        print "Offset byte 1: ", str(i1), " Byte: ", repr(byte_1)
                        print "Offset byte 2: ", str(i2), " Byte: ", repr(byte_2)
                        print "Offset byte 3: ", str(i3), " Byte: ", repr(byte_3)
                        return data_plus_3
def getlen(mm, idatindex):
    return int("0x" + mm[idatindex-4:idatindex].encode("hex"), 0)

idat_chunks = []

f = open('/home/giulio/CTF/Plaid5/forensics/original.png', "r+b")
mm = mmap.mmap(f.fileno(), 0)
#
# L | IDAT | DATA | CHECKSUM ---> {L} {DATA, CHECKSUM, L} {DATA, CHECKSUM, L} ... {DATA, CHECKSUM}
#
shitgotreal = mm.read(mm.size()).split("Adobe Fireworks CS6")[1][4:].split("IEND")[0].split("IDAT")

for cont, idat in [ (x,shitgotreal[x])  for x in range(1, len(shitgotreal))]:
    length = shitgotreal[cont-1][-4:]
    data = idat[:-8]
    checksum = idat[-8:-4]
    idat_chunks.append(IDATChunk(cont,length, data, checksum))
for x in idat_chunks:
    print "IDAT " + str(x.counter) + ": ..."
    getCorrectData(x)
    print "|------|"
{% endhighlight %}
