# JA3 - A method for profiling SSL/TLS Clients

JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

This repo includes JA3 scripts for [Bro/Zeek](https://www.bro.org/) and [Python](https://www.python.org/).

JA3 support has also been added to:  
[Moloch](http://molo.ch/)  
[Trisul NSM](https://github.com/trisulnsm/trisul-scripts/tree/master/lua/frontend_scripts/reassembly/ja3)  
[NGiNX](https://github.com/fooinha/nginx-ssl-ja3)  
[MISP](https://github.com/MISP)  
[Darktrace](https://www.darktrace.com/)  
[Suricata](https://suricata-ids.org/tag/ja3/)  
[Elastic.co Packetbeat](https://www.elastic.co/guide/en/beats/packetbeat/master/exported-fields-tls.html)  
[Splunk](https://www.splunk.com/blog/2017/12/18/configuring-ja3-with-bro-for-splunk.html)  
[MantisNet](https://www.mantisnet.com/)  
[ICEBRG](http://icebrg.io/)  
[Redsocks](https://www.redsocks.eu/)  
[NetWitness](https://github.com/timetology/nw/tree/master/parsers/ssl_ja3)  
[ExtraHop](https://www.extrahop.com/)  
[Vectra Cognito Platform](https://vectra.ai/)  
[Corvil](https://www.corvil.com/blog/2018/environmentally-conscious-understanding-your-network)  
[Java](https://github.com/lafaspot/ja3_4java)  
and more...  


## Examples

JA3 fingerprint for the standard Tor client:  
```
e7d705a3286e19ea42f587b344ee6865
```
JA3 fingerprint for the Trickbot malware:
```
6734f37431670b3ab4292b8f60f29984
```
JA3 fingerprint for the Emotet malware:
```
4d7a28d6f2263ed61de88ca66eb011e3
```

While destination IPs, Ports, and X509 certificates change, the JA3 fingerprint remains constant for the client application in these examples across our sample set. Please be aware that these are just examples, not indicative of all versions ever.

## Lists

Lists of hundreds of known JA3's and their associated applications can be found [here](https://github.com/salesforce/ja3/tree/master/lists). Please be aware that these lists are intended to be used as an example of what is possible and not as an intel feed.

## How it works

TLS and it’s predecessor, SSL, I will refer to both as “SSL” for simplicity, are used to encrypt communication for both common applications, to keep your data secure, and malware, so it can hide in the noise. To initiate a SSL session, a client will send a SSL Client Hello packet following the TCP 3-way handshake. This packet and the way in which it is generated is dependant on packages and methods used when building the client application. The server, if accepting SSL connections, will respond with a SSL Server Hello packet that is formulated based on server-side libraries and configurations as well as details in the Client Hello. Because SSL negotiations are transmitted in the clear, it’s possible to fingerprint and identify client applications using the details in the SSL Client Hello packet.

JA3 is a method of TLS fingerprinting that was inspired by the [research](https://blog.squarelemon.com/tls-fingerprinting/) and works of [Lee Brotherston](https://twitter.com/synackpse) and his TLS Fingerprinting tool: [FingerprinTLS](https://github.com/LeeBrotherston/tls-fingerprinting/tree/master/fingerprintls). 

JA3 gathers the decimal values of the bytes for the following fields in the Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. It then concatenates those values together in order, using a "," to delimit each field and a "-" to delimit each value in each field.

The field order is as follows:
```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```
Example:
```    
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
```
If there are no SSL Extensions in the Client Hello, the fields are left empty. 

Example:
```   
769,4-5-10-9-100-98-3-6-19-18-99,,,
```
These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.
```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
```
We also needed to introduce some code to account for Google’s GREASE (Generate Random Extensions And Sustain Extensibility) as described [here](https://tools.ietf.org/html/draft-davidben-tls-grease-01). Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem.  JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.

## JA3S

JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients. 

JA3S uses the following field order:
```
SSLVersion,Cipher,SSLExtension
```
With JA3S it is possible to fingerprint the entire cryptographic negotiation between client and it's server by combining JA3 + JA3S. That is because servers will respond to different clients differently but will always respond to the same client the same.

For the Trickbot example:
```
JA3 = 6734f37431670b3ab4292b8f60f29984 ( Fingerprint of Trickbot )
JA3S = 623de93db17d313345d7ea481e7443cf ( Fingerprint of Command and Control Server Response )
```
For the Emotet example:
```
JA3 = 4d7a28d6f2263ed61de88ca66eb011e3 ( Fingerprint of Emotet )
JA3S = 80b3a14bccc8598a1f3bbe83e71f735f ( Fingerprint of Command and Control Server Response )
```

In these malware examples, the command and control server always responds to the malware client in exactly the same way, it does not deviate. So even though the traffic is encrypted and one may not know the command and control server's IPs or domains as they are constantly changing, we can still identify, with reasonable confidence, the malicious communication by fingerprinting the TLS negotiation between client and server. Again, please be aware that these are examples, not indicative of all versions ever, and are intended to illustrate what is possible.

## Intriguing Possibilities

JA3 is a much more effective way to detect malicious activity over SSL than IP or domain based IOCs. Since JA3 detects the client application, it doesn’t matter if malware uses DGA (Domain Generation Algorithms), or different IPs for each C2 host, or even if the malware uses Twitter for C2, JA3 can detect the malware itself based on how it communicates rather than what it communicates to.

JA3 is also an excellent detection mechanism in locked-down environments where only a few specific applications are allowed to be installed. In these types of environments one could build a whitelist of expected applications and then alert on any other JA3 hits.

For more details on what you can see and do with JA3 and JA3S, please see this DerbyCon 2018 talk: https://www.youtube.com/watch?v=NI0Lmp0K1zc

Please contact me on twitter @4A4133 or over email, let me know what you find and if you have any feature requests. 

___  
### JA3 Created by

[John B. Althouse](mailto:jalthouse@salesforce.com)  
[Jeff Atkinson](mailto:jatkinson@salesforce.com)  
[Josh Atkins](mailto:j.atkins@salesforce.com)  

Please send questions and comments to **[John B. Althouse](mailto:jalthouse@salesforce.com)**.

