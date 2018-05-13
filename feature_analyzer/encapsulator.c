#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "nf10_reg_acc.h"
#include "reg_defines_openflow_switch.h"

#define GENERAL 0
#define TCP 1
#define ICMP 2
#define DNS 3


struct features
{
	int protocol;
	double f_iat_ratio;
	double p_iat_ratio;
	double ppf_ratio;
	double dns_res_size_ratio;
	int dns_res_num;
	int pkt_num;
	double pkt_size_avg;
};

int main(int argc, char *argv[])
{
	struct sockaddr_in ctrlr_sockaddr;
	struct features features;
	int ctrlr_socket;
	char buf[100];

	char* json_format_str =
		"{"
		"\"F_IAT\":%.4f,"
		"\"P_IAT\":%.4f,"
		"\"PPF\":%.4f,"
		"\"DNS_RES_SIZE\":%.4f,"
		"\"DNS_RES_NUM\":%d,"
		"\"PKT_NUM\":%d,"
		"\"PKG_SIZE_AVG\":%d"
		"}";

	char* ctrlr_addr = "127.0.0.1";
	int ctrlr_port = 5555;

	printf("Feature analyzer - ESRC Lab\n");
	if (argc > 1) {
		ctrlr_addr = argv[1];
		if (argc > 2) {
			ctrlr_port = strtol(argv[2], NULL, 10);
		}
	}

	ctrlr_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ctrlr_socket < 0) {
		printf("socket failed\n");
		return -1;
	}

	ctrlr_sockaddr.sin_family = AF_INET;
	ctrlr_sockaddr.sin_addr.s_addr = inet_addr(ctrlr_addr);
	ctrlr_sockaddr.sin_port = htons(ctrlr_port);
	if (connect(ctrlr_socket, (struct sockaddr *) &ctrlr_sockaddr, sizeof(ctrlr_sockaddr)) < 0) {
		printf("connect failed\n");
		return -1;
	}

	features.protocol = GENERAL;

	while (1) {

		unsigned int x = nf10_reg_rd(NUM_SUITABLE_F_IAT_REG);
		unsigned int y = nf10_reg_rd(NUM_TOTAL_F_IAT_REG);
		features.f_iat_ratio = y ? (float) x / y : 0;

		x = nf10_reg_rd(NUM_SUITABLE_P_IAT_REG);
		y = nf10_reg_rd(NUM_TOTAL_P_IAT_REG);
		features.p_iat_ratio = y ? (float) x / y : 0;

/*
		x = nf10_reg_rd(NUM_SUITABLE_PPF_REG);
		y = nf10_reg_rd(NUM_TOTAL_PPF_REG);
		icmp_features.ppf_ratio = y ? (float) x / y : 0;
*/

		features.ppf_ratio = 0;

		x = nf10_reg_rd(SUITABLE_DNS_RESPONSE_REG);
		y = nf10_reg_rd(TOTAL_DNS_RESPONSE_REG);
		features.dns_res_num = y;
		features.dns_res_size_ratio = y ? (float) x / y : 0;

		x = nf10_reg_rd(TOTAL_PKT_LEN_REG);
		y = nf10_reg_rd(CNT_PKT_REG);
		features.pkt_num = y;
		features.pkt_size_avg = y ? (float) x / y : 0;

		sprintf(buf, json_format_str, \
			features.f_iat_ratio, \
			features.p_iat_ratio, \
			features.ppf_ratio, \
			features.dns_res_size_ratio, \
			features.dns_res_num, \
			features.pkt_num, \
			features.pkt_size_avg \
			);
		send(ctrlr_socket, buf, strlen(buf), 0);

		sleep(6);
	}
	return 0;
}
