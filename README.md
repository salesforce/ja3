# JA3 - A method for profiling SSL/TLS Clients

JA3 was invented at Salesforce in 2017. However, the project is no longer being actively maintained by Salesforce. Its original creator, John Althouse, maintains the latest in TLS client fingerprinting technology at [FoxIO-LLC](https://github.com/FoxIO-LLC/ja4).

JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

Before using, please read this blog post: [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

This repo includes JA3 and JA3S scripts for [Zeek](https://www.zeekurity.org/) and [Python](https://www.python.org/). You can find a nice Rust implementation of the JA3 algorithm [here](https://github.com/jabedude/ja3-rs)

JA3 support has also been added to:  
[Moloch](http://molo.ch/)  
[Trisul NSM](https://github.com/trisulnsm/trisul-scripts/tree/master/lua/frontend_scripts/reassembly/ja3)  
[NGiNX](https://github.com/fooinha/nginx-ssl-ja3)
[BFE](https://github.com/bfenetworks/bfe)
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
[Go](https://github.com/open-ch/ja3)  
[Security Onion](https://securityonion.net/)   
[AIEngine](https://bitbucket.org/camp0/aiengine)  
[RockNSM](https://rocknsm.io/)  
[Corelight](https://www.corelight.com/products/software)  
[VirusTotal](https://blog.virustotal.com/2019/10/in-house-dynamic-analysis-virustotal-jujubox.html#ja3)  
[SELKS](https://www.stamus-networks.com/selks-6)  
[Stamus Networks](https://www.stamus-networks.com/)  
[IBM QRadar Network Insights (QNI)](https://community.ibm.com/community/user/security/blogs/tom-obremski1/2020/10/23/qni-ja3-ja3s-for-network-encryption)  
[InQuest](https://inquest.net)  
[Cloudflare](https://developers.cloudflare.com/bots/concepts/ja3-fingerprint/)  
[AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-threat-signature.html)  
[Azure Firewall](https://learn.microsoft.com/en-us/azure/firewall/idps-signature-categories)  
[AWS WAF](https://aws.amazon.com/about-aws/whats-new/2023/09/aws-waf-ja3-fingerprint-match/)  
[Google Cloud](https://cloud.google.com/load-balancing/docs/https/custom-headers-global)  
[Rama](https://ramaproxy.org)  
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

Example lists of known JA3's and their associated applications can be found [here](https://github.com/salesforce/ja3/tree/master/lists).  

A more up-to-date crowd sourced method of gathering and reporting on JA3s can be found at [ja3er.com](https://ja3er.com).  

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

For more details on what you can see and do with JA3 and JA3S, please see this DerbyCon 2018 talk: https://www.youtube.com/watch?v=NI0Lmp0K1zc or this [blog post.](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

Please contact me on twitter @4A4133 or over email, let me know what you find and if you have any feature requests. 

___  
### JA3 Created by

[John Althouse](https://www.linkedin.com/in/johnalthouse/)  
[Jeff Atkinson](https://www.linkedin.com/in/annh/)  
[Josh Atkins](https://www.linkedin.com/in/joshratkins/)  

Please send questions and comments to **[John Althouse](https://twitter.com/4A4133)**.

