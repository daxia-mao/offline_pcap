#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

/* ----- Global Variable ----- */
struct sockaddr_in source, dest;
int total_count = 0, tcp_count = 0, udp_count = 0, other_count = 0;

void print_ethernet_header(const u_char *buffer, int size){
	struct ethhdr *eth = (struct ethhdr *)buffer;
	uint16_t type = ntohs(eth->h_proto);
	fprintf(stdout , "Ethernet Header\n");
	fprintf(stdout , "-----> # Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(stdout , "-----> # Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(stdout , "-----> # Ethernet Type       : 0x%04X \n",type);
}

void print_ip_header(const u_char *buffer, int size){


	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(stdout, "\n");
	fprintf(stdout , "IP Header\n");
	fprintf(stdout , "-----> # Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(stdout , "-----> # Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_udp_header(const u_char *buffer, int size){

	struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	struct udphdr *udph=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

	fprintf(stdout, "\n");
	fprintf(stdout , "UDP Header\n");
	fprintf(stdout , "-----> # Source Port      : %u\n",ntohs(udph->source));
	fprintf(stdout , "-----> # Destination Port : %u\n",ntohs(udph->dest));
}

void print_tcp_header(const u_char *buffer, int size){

	struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

	fprintf(stdout, "\n");
	fprintf(stdout , "TCP Header\n");
	fprintf(stdout , "-----> # Source Port      : %u\n",ntohs(tcph->source));
	fprintf(stdout , "-----> # Destination Port : %u\n",ntohs(tcph->dest));
}

/* ----- args:所傳的額外的參數, header:封包標頭中的一些資訊, content:封包中的實際資料 -----*/
void cllback_pcap(u_char *args, const struct pcap_pkthdr *header, const u_char *content){
	
	int size = header->len;

	struct iphdr *iph = (struct iphdr*)(content + sizeof(struct ethhdr));
	++total_count;

	struct tm *ltime;
	char timestr[80];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d, %H:%M:%S", ltime);


	switch(iph->protocol){
		case 6:		/* TCP */
			++tcp_count;
			fprintf(stdout, "*-------------------- TDP Pakect --------------------*\n");
			print_ethernet_header(content, size);
			print_ip_header(content, size);
			print_tcp_header(content, size);
			break;

		case 17:	/* UDP */
			fprintf(stdout, "*-------------------- UDP Pakect --------------------*\n");
			print_ethernet_header(content, size);
			print_ip_header(content, size);
			print_udp_header(content, size);
			++udp_count;
			break;
		default:
			print_ethernet_header(content, size);
			++other_count;
			break;
	}
	fprintf(stdout, "\nTimestamp\n");
	fprintf(stdout,"-----> # Timestamp	:%s:%.6d\n", timestr, (int)header->ts.tv_usec);
	fprintf(stdout, "*----------------------------------------------------*\n\n");
}

int main(int argc, char *argv[]){
	
	if(argc != 2){
		fprintf(stderr, "usage: ./offline_pcap <filename>\n");
		exit(1);
	}

	/*
	-----
	函數原型：
	pcap_t *pcap_open_offline(const char *fname, char *errbuf);
	# 返回值：成功則傳回libpcap handle，失敗則回傳NULL，錯誤訊息在errbuf
	# 參數：fname為檔案路徑，errbuf為錯誤訊息
	# 功能：打開離線檔案的handle
	-----
	*/
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filename = argv[1]; 
	pcap_t *handle = pcap_open_offline(filename, errbuf);

	if(handle == NULL){
		fprintf(stderr, "pcap_open_offline() error: \n%s\n", errbuf);
		exit(1);
	}

	/* 
	----- 
	函數原型：
	int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
	返回值：成功回傳0，失敗回傳-1，錯誤訊息由pcap_getter()取得
	參數：
	# cnt：需要抓取的個數，若設為-1，相當於不斷從目標抓包。
	# callback：封包抓到後交給此callback函數處理
	# user: 可自定義一些參數傳遞給callback 
	-----
	*/

	pcap_loop(handle, -1, cllback_pcap, NULL);

	fprintf(stdout, "*---------- Packet Type Count ----------*");
	printf("\nTCP Type: %d\nUDP Type: %d\nOthers Type: %d\nTotal Count: %d\n", tcp_count, udp_count, other_count, total_count);
	fprintf(stdout, "*---------------------------------------*\n");


	return 0;

}

