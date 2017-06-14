JA3 is a standard for creating SSL client fingerprints in an easy to produce and sharable way.  
To be used for whitelists and blacklists, to be shared as threat intel.

JA3 takes the decimal value of the hex in the SSL Client Hello packet, concatenates certain values together, in order, delimited by a "," for each field and a "-" for each value.  
The order is as follows:  
*SSLVersion,Cipher1-Cipher2-Cipher3-etc,SSLExtension1-SSLExtension2,EllipticCurve1-EllipticCurve2,EllipticCurveFormat1-EllipticCurveFormat2*

Example:
> 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0

If there are no SSL Extensions in the Client Hello, the "," delimiters persist. Example:  
> 769,4-5-10-9-100-98-3-6-19-18-99,,,

These strings are then MD5 hashed to produce an easily consumable and sharable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.  
> ada70206e40642a3e4461f35503241d5  
> de350869b8c85de67a350c8d186f11e6

We have support for Bro and Python. Suricata and others are in the works.

Created by  
Jeff Atkinson  
Josh Atkins  
John B. Althouse  
