CryptoAttacker
==================

CryptoAttacker helps detect and exploit some common crypto flaws.

 - Active Scanning to detect padding Oracle attacks
 - Active Scanning capabilities to detect input being encrypted with ECB and reflected back (can be slow)
 - Attack tab to encrypt/decrypt padding oracles
 - Attack tab to decrypt ECB where you control part of the request

#### Requirements:

I only test this on Burp pro latest version and Jython 2.7 (but please report issues if you have any with different configs)

#### Testing:

For unit testing, I've used https://github.com/SpiderLabs/MCIR/tree/master/cryptomg/ctf/challenge1 for padding oracles. 
For ECB I have a similar script.

Please report any cases with URIs or source if possible, and I will look at these.


#### Changelog

**0.01:**
 - Alpha Release - tested with unit tests and a few sites, but have not yet tested broadly.