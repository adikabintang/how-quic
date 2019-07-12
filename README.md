# how-quic

Measuring end-to-end QUIC RTT from QUIC's spin bit. In this way, we can observe the end-to-end RTT, even as a middleman. Run it in a proxy machine, load balancer, router, etc., and we can observe end-to-end RTT.

Written in C with libpcap library.

**warning**: To anyone who sees this, please note this project is written with *learning* goal, not *production* goal.

Dependencies:
1. [libpcap](https://www.tcpdump.org/)
2. [log.c](https://github.com/rxi/log.c)
3. [Criterion unit test](https://github.com/Snaipe/Criterion)