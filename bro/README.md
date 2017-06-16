ja3.bro will add the field "ja3" to the end of ssl.log.  
If you'd like to get more in-depth with the SSL Client Hello fields, uncomment the lines under both "LOG FIELD VALUES"  
This script has been tested on Bro 2.4.1 and 2.5.

intel_ja3.bro will add INTEL::JA3 to the Bro Intel Framwork allowing you to import JA3 fingerprints directly into your intel feed.
intel_ja3.bro should be loaded after ja3.bro.

### JA3 created by

Jeff Atkinson (jatkinson@salesforce.com)

Josh Atkins (joshua.atkins@salesforce.com)

John B. Althouse (jalthouse@salesforce.com)

Please send questions and comments to **John B. Althouse**.
