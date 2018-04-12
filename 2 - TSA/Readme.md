 
# GMT Timestamp Server in Python

An implementation of trusted timestamping authority in Python 3.

References:

1. [Trusted Timestamping - Wikipedia](https://en.wikipedia.org/wiki/Trusted_timestamping)

2. [RFC 3161](http://tools.ietf.org/html/rfc3161)

## Flow

1. First run the timestamp server: `python3 server.py`
2. In another terminal, run the requester client: `python3 client_requester.py filename.txt`
3. A new file named `filename_stamped.txt` will be created.
4. To verify, run: `python3 client_verifiery.py filename_stamped.txt`

## Cheating

There is a bug in my RSA implementation which leads to non-determinism in the process. Sometimes the verification works correctly, sometimes it just fails, and I wasn't able to figure out why. 

The core RSA algorithm is simple - the tricky part is converting input strings to integers, and back again, which is further complicated by the fact that integers need to be in a suitable "range". I tried doing all sorts of crazy fiddling, but yeah, not my forte! 

I didn't have time to muck around with this so I just used `base64` encoding, which makes the text look "encrypted"

If you need to implement this too, begin by looking at how i2osp, os2ip etc. work and how they're used. There is a python implementation [here](https://github.com/bdauvergne/python-pkcs1/).

By the way, as it turned out, we didn't even have to implement our own RSA for this. **We could just have used some library**.

## Assignment Demo

The TAs asked us to modify contents of the stamped file to show that verification failed.

This is where base64 came to bite us in the ass. I removed a few characters and base64 decoding just failed. After trying this multiple times, Nichit suggested we could just replace characters, rather than removing them. That still counts as modification, right. That seemed to work!

As it turns out Python also pads it with length etc.