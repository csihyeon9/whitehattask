#include <stdlib.h>       // 표준 라이브러리 함수와 데이터 타입을 정의합니다.
#include <pcap.h>         // PCAP (Packet Capture) 라이브러리를 사용하기 위한 헤더 파일입니다.
#include <netinet/ip.h>   // IP 헤더 구조체를 정의합니다.
#include <netinet/tcp.h>  // TCP 헤더 구조체를 정의합니다.
#include <netinet/if_ether.h> // Ethernet 헤더 구조체를 정의합니다.
#include <ctype.h>        // 문자 관련 함수를 사용하기 위한 헤더 파일입니다.

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Ethernet 헤더 추출
    struct ether_header *eth_header = (struct ether_header *)packet;

    // IP 헤더 추출
    struct ip *ip_packet = (struct ip *)(packet + ETHER_HDR_LEN);

    // TCP 헤더 추출
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_packet->ip_hl << 2));

    // Ethernet 헤더 정보 출력
    printf("Ethernet Header:\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // IP 헤더 정보 출력
    printf("IP Header:\n");
    printf("Source IP: %s\n", inet_ntoa(ip_packet->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_packet->ip_dst));

    // TCP 헤더 정보 출력
    printf("TCP Header:\n");
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

    // 메시지 데이터 출력
    printf("Message:\n");
    const unsigned char *message = packet + ETHER_HDR_LEN + (ip_packet->ip_hl << 2) + (tcp_header->th_off << 2);
    int message_length = pkthdr->len - ETHER_HDR_LEN - (ip_packet->ip_hl << 2) - (tcp_header->th_off << 2);
    for (int i = 0; i < message_length; i++) {
        if (isprint(message[i])) {
            printf("%c", message[i]);  // 출력 가능한 ASCII 문자는 그대로 출력
        } else {
            printf(".");  // 출력 불가능한 문자는 '.'으로 대체하여 출력
        }
    }
    printf("\n\n");  // 줄 바꿈으로 패킷 간 간격 표시
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 네트워크 디바이스 리스트 조회
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 첫 번째 디바이스 선택
    char *dev = alldevs->name;

    // 네트워크 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 캡처 및 처리
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
