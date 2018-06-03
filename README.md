fakeDNS
===========

Simple DNS server that supports regular-expressions in records definitions.
Based on twisted python engine.

## Usage

```
pip install twisted
git clone ...
cd fakedns
vi ./hosts
python ./dns.py
```

'self' and 'host' records in ./hosts will replaced by your server's IP address.

## Testing

```
dig -p 53 @127.0.0.1 example.com A +short
dig -p 53 @127.0.0.1 example.com AAAA +short
dig -p 53 @127.0.0.1 random.example.com A +short
```
