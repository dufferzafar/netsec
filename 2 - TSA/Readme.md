 
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