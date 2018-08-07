## Features
- **ja3.bro** will add the field "ja3" to ssl.log.  
  - It can also append fields used by JA3 to ssl.log

- **intel_ja3.bro** will add INTEL::JA3 to the Bro Intel Framwork
  - This will allow you to import JA3 fingerprints directly into your intel feed.
  
- **ja3s.bro** will add the field "ja3s" to ssl.log, JA3 for the server hello.
  - It can also append fields used by JA3S to ssl.log.

- Tested on Bro 2.4.1, 2.5, and 2.5.1

## Installation
- If you're running Bro >=2.5 or a Bro product like Corelight, you can install by using the Bro Package Manager and this one simple command:
```bash
bro-pkg install ja3
```

- For everyone else, download the files to bro/share/bro/site/ja3 and add this line to your local.bro script:
```bash
@load ./ja3
```

## Configuration

By default ja3.bro will only append ja3 to the ssl.log. However, if you would like to log all aspects of the SSL Client Hello Packet, uncomment the following lines in ja3.bro
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
The same changes can be made in ja3s.bro as well.

___  
### JA3 Created by

[John B. Althouse](mailto:jalthouse@salesforce.com)  
[Jeff Atkinson](mailto:jatkinson@salesforce.com)  
[Josh Atkins](mailto:j.atkins@salesforce.com)  

Please send questions and comments to **[John B. Althouse](mailto:jalthouse@salesforce.com)**.

