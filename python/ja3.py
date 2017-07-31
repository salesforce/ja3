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

from hashlib import md5

import struct
import traceback
import dpkt
import binascii
import socket
import argparse

DEBUG = False
TLS_HANDSHAKE = 22

# Well...this is neat
# https://tools.ietf.org/html/draft-davidben-tls-grease-00
GREASE_table = {
    0x0a0a : True,
    0x1a1a : True,
    0x2a2a : True,
    0x3a3a : True,
    0x4a4a : True,
    0x5a5a : True,
    0x6a6a : True,
    0x7a7a : True,
    0x8a8a : True,
    0x9a9a : True,
    0xaaaa : True,
    0xbaba : True,
    0xcaca : True,
    0xdada : True,
    0xeaea : True,
    0xfafa : True
}


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

    data = bytearray(data)

    if len(data) < 2:

        if GREASE_table.get(data[0], False):
            return ""

        return str(data[0])

    for i in list(range(0, len(data), 2)):
        val = (data[i] << 8) | data[i + 1]

        if GREASE_table.get(val, False):
            continue

        int_vals.append(val)

    return "-".join([str(x) for x in int_vals])


def print_ja3_hashes(cap, any_port=False):

    def convert_ip(val):
        try:
            return socket.inet_ntop(socket.AF_INET, val)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, val)

    for ts, buf in cap:

        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # print('pkt: %d' % (pkt_count))

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        if not (tcp.dport == 443 or tcp.sport == 443 or any_port):
            continue

        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
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
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                continue

            if DEBUG:
                print("Hello DATA: %s" % binascii.hexlify(record.data))

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                continue

            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                continue

            ch = handshake.data

            if DEBUG:
                print("Handshake DATA: %s" % binascii.hexlify(ch.data))

            buf, ptr = parse_variable_array(ch.data, 1)
            buf, ptr = parse_variable_array(ch.data[ptr:], 2)
            ja3 = ["%d" % ch.version]
            ja3.append(convert_to_ja3_seg(buf))

            if hasattr(ch, "extensions"):

                exts = []
                ec = ""
                ec_pf = ""

                for ext_val, ext_data in ch.extensions:

                    if not GREASE_table.get(ext_val):
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
            ja_digest = md5(ja3.encode()).hexdigest()
            print("[%s:%s] JA3: %s --> %s" % (
                convert_ip(ip.dst),
                tcp.dport,
                ja3,
                ja_digest
            ))


def main(args):

    with open(args.pcap, 'rb') as fp:
        capture = get_pcap_reader(fp)
        print_ja3_hashes(capture, any_port=args.any_port)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "A python script for extracting JA3 fingerprints from pcap files"
        )
    )

    parser.add_argument(
        "-a",
        "--any_port",
        required=False,
        action="store_true",
        default=False,
        help="Look for client hellos on any port instead of just 443"
    )
    parser.add_argument(
        "pcap",
        help="The pcap file to process"
    )

    args = parser.parse_args()
    try:
        main(args)
    except Exception:
        traceback.print_exc()
