#!/usr/bin/env python

#####
# Author: Tommy Stallings (tommy.stallings@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
#####

from collections import defaultdict
from hashlib import md5

import os
import sys
import struct
import traceback
import dpkt
import binascii

DEBUG = False
TLS_HANDSHAKE = 22


def get_pcap_reader(fp):
    return dpkt.pcap.Reader(fp)


# Borrowed from dpkt.ssl - lightly modified
def parse_variable_array(buf, lenbytes):

    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    # first have to figure out how to parse length
    assert lenbytes <= 4  # pretty sure 4 is impossible, too
    size_format = _SIZE_FORMATS[lenbytes - 1]
    padding = b'\x00' if lenbytes == 3 else b''
    # read off the length
    size = struct.unpack(size_format, padding + buf[:lenbytes])[0]
    # read the actual data
    data = buf[lenbytes:lenbytes + size]
    # if len(data) != size: insufficient data
    return data, size + lenbytes


def convert_to_ja3_seg(data):

    int_vals = []

    if len(data) < 2:
        return str(ord(data[0]))

    for i in xrange(0, len(data), 2):
        val = (ord(data[i]) << 8) | ord(data[i + 1])
        int_vals.append(val)

    return "-".join([str(x) for x in int_vals])


def print_ja3_hashes(cap):

    for ts, buf in cap:

        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # print 'pkt: %d' % (pkt_count)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data
        # this will cause a miss for non port 443 ssl traffic
        if tcp.dport != 443 and tcp.sport != 443:
            continue

        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        if ord(tcp.data[0]) != TLS_HANDSHAKE:
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception, e:
            continue
        except dpkt.dpkt.NeedData, e:
            continue

        if len(records) <= 0:
            continue

        for record in records:

            # TLS handshake only
            if record.type != TLS_HANDSHAKE:
                continue

            if len(record.data) == 0:
                continue

            # Client Hello only
            if ord(record.data[0]) != 1:
                continue

            if DEBUG:
                print "Hello DATA: %s" % binascii.hexlify(record.data)

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData, e:
                continue

            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                continue

            ch = handshake.data

            if DEBUG:
                print "Handshake DATA: %s" % binascii.hexlify(ch.data)

            buf, ptr = parse_variable_array(ch.data, 1)
            buf, ptr = parse_variable_array(ch.data[ptr:], 2)
            ja3 = ["%d" % ch.version]
            ja3.append(convert_to_ja3_seg(buf))
            if hasattr(ch, "extensions"):
                exts = []
                ec = ""
                ec_pf = ""
                for ext_val, ext_data in ch.extensions:
                    exts.append(ext_val)
                    if ext_val == 0x0a:
                        a, b = parse_variable_array(ext_data, 2)
                        ec = convert_to_ja3_seg(a)
                    elif ext_val == 0x0b:
                        a, b = parse_variable_array(ext_data, 1)
                        ec_pf = convert_to_ja3_seg(a)

                ja3.append("-".join([str(x) for x in exts]))
                ja3.append(ec)
                ja3.append(ec_pf)
            else:
                # No extensions, so no curves or points.
                ja3.extend(["", "", ""])

            ja3 = ",".join(ja3)
            ja_digest = md5(ja3).hexdigest()
            print "JA3: %s --> %s" % (ja3, ja_digest)


def main(argv):

    if len(argv) != 2:
        print "Tool to generate JA3 fingerprints observed in a pcap."
        print ""
        print "Usage: %s <pcap file>" % argv[0]
        print ""
        sys.exit(1)

    with open(argv[1], 'rb') as fp:
        capture = get_pcap_reader(fp)
        print_ja3_hashes(capture)


if __name__ == "__main__":

    try:
        main(sys.argv)
    except Exception, e:
        traceback.print_exc()
