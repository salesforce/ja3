## Features
- **ja3.bro** will add the field "ja3" to the end of ssl.log.  
  - It can also append fields used by JA3 to ssl.log

- **intel_ja3.bro** will add INTEL::JA3 to the Bro Intel Framwork
  - This will allow you to import JA3 fingerprints directly into your intel feed.

- Tested on Bro 2.4.1 and Bro 2.5

## Installation
- Download files to bro/share/bro/site/ja3

- Add this line to your local.bro script
```
@load ./ja3
```

## Configuration

By defualt ja3.bro will only append ja3 to the ssl.log. However, if you would like to log all aspects of the SSL Client Hello Packet, uncomment the following lines in ja3.bro
```bash
#  ja3_version:  string &optional &log;
#  ja3_ciphers:  string &optional &log;
#  ja3_extensions: string &optional &log;
#  ja3_ec:         string &optional &log;
#  ja3_ec_fmt:     string &optional &log;
```
...
```bash
#c$ssl$ja3_version = cat(c$tlsfp$client_version);
#c$ssl$ja3_ciphers = c$tlsfp$client_ciphers;
#c$ssl$ja3_extensions = c$tlsfp$extensions;
#c$ssl$ja3_ec = c$tlsfp$e_curves;
#c$ssl$ja3_ec_fmt = c$tlsfp$ec_point_fmt;
```

___  
### JA3 Created by

[John B. Althouse](mailto:jalthouse@salesforce.com)  
[Jeff Atkinson](mailto:jatkinson@salesforce.com)  
[Josh Atkins](mailto:j.atkins@salesforce.com)  

Please send questions and comments to **[John B. Althouse](mailto:jalthouse@salesforce.com)**.

