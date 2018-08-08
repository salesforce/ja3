# @TEST-EXEC: bro -r $TRACES/ssl-curl.pcap ../../../bro
# @TEST-EXEC: btest-diff ssl.log
