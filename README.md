# network_security_codes
[실습 Repository 바로가기](https://github.com/pwnhyo/network_security_codes)

## C_sniffing

1. UDP server<br>
   → 특정 포트로 들어온 UDP 메시지만 받기<br>

2. Raw socket<br>
   → 포트/프로토콜 상관없이 네트워크 패킷 자체를 받기<br>

3. pcap sniff.c<br>
   → libpcap으로 패킷 캡처하고 필터 적용하기<br>

4. pcap sniff_improved.c<br>
   → 캡처한 패킷의 Ethernet/IP 헤더를 직접 해석하기<br>

## C_spoofing

1. UDP client<br>
   → 일반 UDP 소켓으로 특정 서버/포트에 메시지 보내기<br>
   → 출발지 IP와 UDP/IP 헤더는 운영체제가 자동으로 설정함<br>

2. send_raw_ip_packet.c<br>
   → 직접 만든 IP 패킷을 raw socket으로 전송하는 helper 함수<br>
   → `IP_HDRINCL` 옵션을 사용해 커널이 IP 헤더를 새로 만들지 않고, 우리가 만든 IP 헤더를 그대로 보내게 함<br>

3. spoof_udp.c<br>
   → IP/UDP 헤더와 payload를 직접 구성해서 UDP 패킷 보내기<br>
   → 출발지 IP를 임의 값으로 설정하여 spoofed UDP packet 생성<br>

4. sniff_spoof_udp.c<br>
   → PCAP으로 UDP 패킷을 sniff한 뒤, 캡처한 패킷을 기반으로 spoofed reply 생성<br>
   → IP source/destination과 UDP source/destination port를 서로 바꾸고 payload를 수정해 응답처럼 보이는 패킷 전송