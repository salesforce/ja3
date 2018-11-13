# This Bro script adds JA3 to the Bro Intel Framework as Intel::JA3
#
# Author: John B. Althouse (jalthouse@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Intel;

export {
    redef enum Intel::Type += { Intel::JA3 };
}

export {
    redef enum Intel::Where += { SSL::IN_JA3 };
}

@if ( Version::at_least("2.6") || ( Version::number == 20500 && Version::info$commit >= 944 ) )
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
@endif
	{
	if ( c$ssl?$ja3 )
	Intel::seen([$indicator=c$ssl$ja3, $indicator_type=Intel::JA3, $conn=c, $where=SSL::IN_JA3]);
	}
