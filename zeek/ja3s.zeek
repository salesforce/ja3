# This Zeek script appends JA3S (JA3 Server) to ssl.log
# Version 1.0 (August 2018)
# This builds a fingerprint for the SSL Server Hello packet based on SSL/TLS version, cipher picked, and extensions used. 
# Designed to be used in conjunction with JA3 to fingerprint SSL communication between clients and servers.
#
# Authors: John B. Althouse (jalthouse@salesforce.com) Jeff Atkinson (jatkinson@salesforce.com)
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause
#



module JA3_Server;

export {
redef enum Log::ID += { LOG };
}

type JA3Sstorage: record {
       server_version:      count &default=0 &log;
       server_cipher:      count &default=0 &log;
       server_extensions:   string &default="" &log;
};

redef record connection += {
       ja3sfp: JA3Sstorage &optional;
};

redef record SSL::Info += {
  ja3s:            string &optional &log;
# LOG FIELD VALUES #
#  ja3s_version:  string &optional &log;
#  ja3s_cipher:  string &optional &log;
#  ja3s_extensions: string &optional &log;
};


const sep = "-";
event zeek_init() {
    Log::create_stream(JA3_Server::LOG,[$columns=JA3Sstorage, $path="ja3sfp"]);
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
if ( ! c?$ja3sfp )
    c$ja3sfp=JA3Sstorage();
    if ( is_orig == F ) { 
        if ( c$ja3sfp$server_extensions == "" ) {
            c$ja3sfp$server_extensions = cat(code);
        }
        else {
            c$ja3sfp$server_extensions = string_cat(c$ja3sfp$server_extensions, sep,cat(code));
        }
    }
}

@if ( ( Version::number >= 20600 ) || ( Version::number == 20500 && Version::info$commit >= 944 ) )
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=1
@else
event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=1
@endif
{
    if ( !c?$ja3sfp )
    c$ja3sfp=JA3Sstorage();
    c$ja3sfp$server_version = version;
    c$ja3sfp$server_cipher = cipher;
    local sep2 = ",";
    local ja3s_string = string_cat(cat(c$ja3sfp$server_version),sep2,cat(c$ja3sfp$server_cipher),sep2,c$ja3sfp$server_extensions);
    local ja3sfp_1 = md5_hash(ja3s_string);
    c$ssl$ja3s = ja3sfp_1;

# LOG FIELD VALUES #
#c$ssl$ja3s_version = cat(c$ja3sfp$server_version);
#c$ssl$ja3s_cipher = cat(c$ja3sfp$server_cipher);
#c$ssl$ja3s_extensions = c$ja3sfp$server_extensions;
#
# FOR DEBUGGING #
#print "JA3S: "+ja3sfp_1+" Fingerprint String: "+ja3s_string;

}
