# JA3 - A method for profiling SSL/TLS Clients

JA3 is a method for creating SSL/TLS client fingerprints that are easy to produce and can be easily shared for threat intelligence.

This repo includes JA3 scripts for [Bro](https://www.bro.org/) and [Python](https://www.python.org/).

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
and more...  


## Examples

JA3 fingerprint for the standard Tor client:  
```
e7d705a3286e19ea42f587b344ee6865
```
JA3 fingerprint for the Dridex malware:
```
74927e242d6c3febf8cb9cab10a7f889
```
JA3 fingerprint for Metasploit's Meterpreter (Linux):
```
5d65ea3fb1d4aa7d826733d2f2cbbb1d
```

While destination IPs, Ports, and X509 certificates change, the JA3 fingerprint remains constant for the client application in these examples.

## JA3S

JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients.

## Lists

Lists of hundreds of known JA3's and their associated applications can be found [here](https://github.com/salesforce/ja3/tree/master/lists).

## How it works

TLS and it’s predecessor, SSL, I will refer to both as “SSL” for simplicity, are used to encrypt communication for both common applications, to keep your data secure, and malware, so it can hide in the noise. To initiate a SSL session, a client will send a SSL Client Hello packet following the TCP 3-way handshake. This packet and the way in which it is generated is dependant on packages and methods used when building the client application. The server, if accepting SSL connections, will respond with a SSL Server Hello packet that is formulated based on server-side libraries and configurations as well as details in the Client Hello. Because SSL negotiations are transmitted in the clear, it’s possible to fingerprint and identify client applications using the details in the SSL Client Hello packet. It's also possible to fingerprint the entire cryptographic negotiation by combining JA3 + JA3S.

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
These strings are then MD5 hashed to produce an easily consumable and sharable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.
```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
```
We also needed to introduce some code to account for Google’s GREASE (Generate Random Extensions And Sustain Extensibility) as described [here](https://tools.ietf.org/html/draft-davidben-tls-grease-01). Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem.  JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.

JA3S uses the following field order:
```
SSLVersion,Cipher,SSLExtension
```

## Intriguing Possibilities

JA3 is a much more effective way to detect malicious activity over SSL than IP or domain based IOCs. Since JA3 detects the client application, it doesn’t matter if malware uses DGA (Domain Generation Algorithms), or different IPs for each C2 host, or even if the malware uses Twitter for C2, JA3 can detect the malware itself based on how it communicates rather than what it communicates to.

JA3 is also an excellent detection mechanism in locked-down environments where only a few specific applications are allowed to be installed. In these types of environments one could build a whitelist of expected applications and then alert on any other JA3 hits.

For more details on what you can see and do with JA3 and JA3S, please see this Shmoocon 2018 talk: https://youtu.be/oprPu7UIEuk?t=6m44s  
Please contact me on twitter @4A4133 or over email, let me know what you find and if you have any feature requests. 

___  
### JA3 Created by

[John B. Althouse](mailto:jalthouse@salesforce.com)  
[Jeff Atkinson](mailto:jatkinson@salesforce.com)  
[Josh Atkins](mailto:j.atkins@salesforce.com)  

Please send questions and comments to **[John B. Althouse](mailto:jalthouse@salesforce.com)**.

