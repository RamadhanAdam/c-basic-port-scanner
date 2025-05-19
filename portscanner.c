#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>

void port_scanner(char* IP, char* Fp, char* Lp);

int main(int argc, char *argv[])
{

	char srvIP[16] = {0}; //Server IP Address
	char first_Port[6] = {0};
	char last_Port[6] = {0};

	if(argc < 4){
		printf("Please enter the server IP Address and range of ports to be scanned\n");
		printf("USAGE: %s IPV4 First_Port Last_Port\n", argv[0]);
		exit(1);
	}

	strcpy(srvIP,argv[1]); //copying the Server IPV4 address
	strcpy(first_Port,argv[2]); //copying the first port in the port range
	strcpy(last_Port, argv[3]); //copying the last port in the port range

	//Staring Port Scanner
	port_scanner(srvIP, first_Port, last_Port);

	return 0;
}

void port_scanner(char* IP, char* Fp,char* Lp){
	
	struct addrinfo hints, *serv_addr, *temp;
	int sockfd, port, status;
	int first_port = atoi(Fp);
	int last_port = atoi(Lp);
	
	for( port = first_port; port<=last_port; port ++){
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET; //IPV4
		hints.ai_socktype = SOCK_STREAM; //TCP

		//converting port number to string
		char port_str[6];
		snprintf(port_str, sizeof(port_str), "%d", port);
		
		//resolving Ip and port to a list of address structures
		if(getaddrinfo(IP, port_str, &hints, &serv_addr) !=0){
			printf("Error resolving address for port %d\n", port);
			continue;
		}
		
		for(temp = serv_addr; temp !=NULL; temp = temp -> ai_next){
			//creatig sockt using address info
			sockfd = socket(temp -> ai_family,
					temp -> ai_socktype,
					temp -> ai_protocol);

			if(sockfd < 0){
				//if socket creation failed, try next
				continue;
			}
			
			//we try connecting to the current address (IP: Port)
			status = connect(sockfd, temp->ai_addr, temp->ai_addrlen);
			if(status == 0){
				printf("Port %d is Open. \n", port);
				close(sockfd);
				break;
			} else {
				close(sockfd);
			}
		}

		//if none of the connections worked , port is closed 
		if(temp == NULL){
			printf("Port %d is NOT open. \n", port);
		}

		//freeing the address info allocated by getaddrinfo
		freeaddrinfo(serv_addr);

	}	
}
