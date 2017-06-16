# JA3 - A new way to profile SSL Clients


JA3 is a new technique for creating SSL client fingerprints that are easy to produce and can be easily shared for threat intelligence.

### Examples

JA3 fingerprint for the standard Tor client:  
```
e7d705a3286e19ea42f587b344ee6865
```
JA3 fingerprint for the Dyre malware family:
```
55fa82b61806d2e6e9848260de2ecb34
```
While destination IPs, Ports, and X509 certificates change, the JA3 fingerprint remains constant for the client application in these examples.

### How it works

JA3 takes the decimal values of the bytes for certain fields (version, ciphers, extensions, etc.) in the SSL Client Hello packet and concatenates them together, in a particular order, using a "," to delimit each field and a "-" to delimit each value in each field. 

The field order is as follows:
```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```
Example:
    
    769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0

If there are no SSL Extensions in the Client Hello, the fields are left empty. 

Example:
    
    769,4-5-10-9-100-98-3-6-19-18-99,,,

These strings are then MD5 hashed to produce an easily consumable and sharable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.

    769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
    769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6

We have support for Bro and Python. Suricata and others are in the works!
___  
### JA3 Created by

[Jeff Atkinson](jatkinson@salesforce.com)  
[Josh Atkins](joshua.atkins@salesforce.com)  
[John B. Althouse](jalthouse@salesforce.com)

Please send questions and comments to **[John B. Althouse](jalthouse@salesforce.com)**.
