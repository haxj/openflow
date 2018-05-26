#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "nf10_reg_acc.h"
#include "reg_defines_openflow_switch.h"

struct features
{
	int protocol;
	double f_iat_ratio;
	double p_iat_ratio;
	double ppf_ratio;
	double dns_res_size_ratio;
	int dns_res_num;
	int pkt_num;
	int pkt_size_avg;
};

int main(int argc, char *argv[])
{
	struct sockaddr_in ctrlr_sockaddr;
	struct features features;
	int ctrlr_socket;
	char buf[200];
	
	int demo_mode = 0;
	int ts_sec = 0;

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
		if (strcmp(argv[1], "-demo")) {
			demo_mode = 0;
			ctrlr_addr = argv[1];
			if (argc > 2) {
				ctrlr_port = strtol(argv[2], NULL, 10);
			}
		} else {
			demo_mode = 1;
		}
	}

	if (! demo_mode) {
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
	}

	while (1) {
		unsigned int x = nf10_reg_rd(NUM_SUITABLE_F_IAT_REG);
		unsigned int y = nf10_reg_rd(NUM_TOTAL_F_IAT_REG);
		features.f_iat_ratio = y ? (float) x / y : 0;

		printf("F_IAT SUITABLE: %d   TOTAL: %d\n", x, y);

		x = nf10_reg_rd(NUM_SUITABLE_P_IAT_REG);
		y = nf10_reg_rd(NUM_TOTAL_P_IAT_REG);
		features.p_iat_ratio = y ? (float) x / y : 0;

		printf("P_IAT SUITABLE: %d   TOTAL: %d\n", x, y);

		x = nf10_reg_rd(NUM_FLOW_1_PKT);
		y = nf10_reg_rd(NUM_FLOW);
		features.ppf_ratio = y ? (float) x / y : 0;

		printf("PPF SUITABLE: %d   TOTAL: %d\n", x, y);

		features.ppf_ratio = 0;

		x = nf10_reg_rd(SUITABLE_DNS_RESPONSE_REG);
		y = nf10_reg_rd(TOTAL_DNS_RESPONSE_REG);
		features.dns_res_num = y;
		features.dns_res_size_ratio = y ? (float) x / y : 0;

		printf("DNS SUITABLE: %d   TOTAL: %d\n", x, y);

		x = nf10_reg_rd(TOTAL_PKT_LEN_REG);
		y = nf10_reg_rd(CNT_PKT_REG);
		features.pkt_num = y;
		features.pkt_size_avg = y ? x / y : 0;

		printf("TOTAL_LEN: %d\n", x);
		sprintf(buf, json_format_str, \
			features.f_iat_ratio, \
			features.p_iat_ratio, \
			features.ppf_ratio, \
			features.dns_res_size_ratio, \
			features.dns_res_num, \
			features.pkt_num, \
			features.pkt_size_avg \
			);

		if (! demo_mode) {
			send(ctrlr_socket, buf, strlen(buf), 0);
			printf("%d: %s\n", ts_sec, buf);
		} else {
			printf("%d: %s\n", ts_sec, buf);

/*
			printf("OF_IP_TP_PARSE_CNT_0_REG: %d\n", nf10_reg_rd(OF_IP_TP_PARSE_CNT_0_REG));
			printf("OF_IP_TP_PARSE_CNT_1_REG: %d\n", nf10_reg_rd(OF_IP_TP_PARSE_CNT_1_REG));
			printf("OF_IP_TP_PARSE_CNT_2_REG: %d\n", nf10_reg_rd(OF_IP_TP_PARSE_CNT_2_REG));
			printf("OF_IP_TP_PARSE_CNT_3_REG: %d\n", nf10_reg_rd(OF_IP_TP_PARSE_CNT_3_REG));
*/

		}

		sleep(1);
		ts_sec++;
	}
	return 0;
}
