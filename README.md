# how-quic

[![Build Status](https://travis-ci.org/adikabintang/how-quic.svg?branch=master)](https://travis-ci.org/adikabintang/how-quic)

Measuring end-to-end QUIC RTT from QUIC's spin bit. In this way, we can observe the end-to-end RTT, even as a middleman. Run it in a proxy machine, load balancer, router, etc., and we can observe end-to-end RTT.

Written in C with libpcap library.

**warning**: To anyone who sees this, please note this project is written with *learning* goal, not *production* goal.

Some of its limitation:
- The memory consumption always grows as the number of connections grow
  - I don't know how to clear previous connection as the QUIC's connection close is in QUIC payload, which is encrypted ([reference](https://tools.ietf.org/html/draft-ietf-quic-transport-22#page-117))
  - I tried to see what Wireshark is doing for this, but it looks like Wireshark also does the same: it does not clear the previous connection ([reference](https://osqa-ask.wireshark.org/questions/34035/tshark-memory-usage-explanation-needed) and [reference](https://github.com/wireshark/wireshark/blob/aa434673bfd2f45f26394c828558dd0bb9aff718/epan/dissectors/packet-http.c#L961)).  

Dependencies:
1. [libpcap](https://www.tcpdump.org/)
2. [log.c](https://github.com/rxi/log.c)
3. [Criterion unit test](https://github.com/Snaipe/Criterion)