#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <winsock2.h>
#include <iostream>


//http://en.wikipedia.org/wiki/Bit_field

//DNS header structure
struct DNS_HEADER {
	unsigned	short id;		    // identification number
	
	unsigned	char rd     :1;		// recursion desired
	unsigned	char tc     :1;		// truncated message
	unsigned	char aa     :1;		// authoritive answer
	unsigned	char opcode :4;	    // purpose of message
	unsigned	char qr     :1;		// query/response flag
	
	unsigned	char rcode  :4;	    // response code
	unsigned	char cd     :1;	    // checking disabled
	unsigned	char ad     :1;	    // authenticated data
	unsigned	char z      :1;		// its z! reserved
	unsigned	char ra     :1;		// recursion available
	
	unsigned    short q_count;	    // number of question entries
	unsigned	short ans_count;	// number of answer entries
	unsigned	short auth_count;	// number of authority entries
	unsigned	short add_count;	// number of resource entries
};

typedef struct DNS_HEADER DNS_HEADER;

struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};

typedef struct QUESTION QUESTION;

struct DNS_ANSWER {
    char name[255];
    short dns_type;
    short dns_class;
    int ttl;
	char data[255];
};

typedef struct DNS_ANSWER DNS_ANSWER;

//Constant sized fields of the resource record structure
#pragma pack(push, 1)

//Type field of Query and Answer
#define T_A		    1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_CNAME		5		/* canonical name */
#define T_SOA		6		/* start of authority zone */
#define T_PTR		12		/* domain name pointer */
#define T_MX		15		/* mail routing information */
#define T_ANY		255		/* all info */

unsigned char host[32];
char dns_server[32];
unsigned char recursive;
unsigned char querytype;

//Initial size of request
int initialSize;

//The socket (tm)
SOCKET s;

char buffer[1024];

int extractName(char *address, char *name);
void convertName(unsigned char *dns, unsigned char *host);
void setRecursion(char*);
void setQueryType(char*);
void lookupHost();
void sendRequest();
void receiveResponse();
int parseResponse(char *buf, DNS_ANSWER *answers, int startSize, int blocks);


using namespace std;

int main(int argc, char** argv) {

	WSADATA firstsock;
	if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) {
		printf("Failed to initialize WSAStartup. Error Code : %d\n",WSAGetLastError());
		return 1;
	} 

	if (argc !=5) {
		printf("Usage: ./lookup dns_server recursive type host!\n");
		exit(0);
	}


	//We have to resolve ip addresses to their names in order for PTR requests to be answered
	int isIP = 1;
	for(int i=0; i < strlen(argv[4]); i++) {
		if( argv[4][i] == '.' ) continue;
		else 
		if( isalpha(argv[4][i]) ){
		  isIP = 0;
		  break;
		}
	}

	if (!isIP) {
		strncpy((char*)host,argv[4],strlen(argv[4])+1);
	}
	else {
		struct in_addr ipHost;
		ipHost.S_un.S_addr = inet_addr(argv[4]);
		hostent* x = gethostbyaddr( (const char*) &ipHost,sizeof(struct in_addr), AF_INET );
		if (x == NULL) {
			printf("Inexistent IP address.\n");
			exit(0);
		}
		strcpy((char*)host,x->h_name);
	}

	//Set parameters
	strncpy(dns_server,argv[1],strlen(argv[1])+1);
	setRecursion(argv[2]);
	setQueryType(argv[3]);

	cout << "\nSending query to DNS Server:"<< dns_server<<endl;
	cout << "Regarding:" << host << endl << endl;
	
	lookupHost();

	closesocket(s);
	WSACleanup();
	_getch();
	return 0;
}

void setRecursion(char* recursion) {
	if (recursion[0]=='R') {
		recursive = 1;
	}
	else 
	if (recursion[0]=='I') {
			recursive = 0;
	}
	else {
		printf("Illegal parameter. Assuming recursive query.\n");
		recursive = 1;
	}

	printf("\nRecursion:%d\n", recursive);
}

void setQueryType(char* queryType) {
	if (strcmp(queryType,"A")==0) {
		querytype = T_A;
	}
	else
	if (strcmp(queryType,"CNAME")==0) {
		querytype = T_CNAME;
	}
	else
	if (strcmp(queryType,"NS")==0) {
		querytype = T_NS;
	}
	else
	if (strcmp(queryType,"MX")==0) {
		querytype = T_MX;
	}
	else
	if (strcmp(queryType,"SOA")==0)	{
		querytype = T_SOA;
	}
	else
	if (strcmp(queryType,"PTR")==0)	{
		querytype = T_PTR;
	}
	else
	if (strcmp(queryType,"ANY")==0)	{
		querytype = T_ANY;
	}
	else {
		printf("Illegal arguments. Assuming 'A'.\n");
		querytype = T_A;
	}
	//printf("Query type: %s.\n",queryType);
}

//http://www.zytrax.com/books/dns/ch15/
//http://svn.xmpp.ru/repos/bombus-ng/trunk/src/dnsquery.cpp

//converts 3www6google3com back to www.google.com
int extractName(char *address, char *name) {
    int position = 0;
    int i = 0;
    int length = 0;
    unsigned char *tempAddress;

    memset(name, 0, 255);
    tempAddress = (unsigned char *) address;

    int hasPointer = 0;
    unsigned int j = 0;

    while (tempAddress[i] > 0) {
		if (tempAddress[i] >= 192) {
			unsigned short pointer;
			memcpy(&pointer, tempAddress + i, 2);
			pointer = ntohs(pointer);
			pointer -= (32768 + 16384);
			tempAddress = (unsigned char *) (buffer + pointer);
			i = 0;

			if (hasPointer == 0) {
				length = length + 2;
			}
			hasPointer = 1;
		}

		if (tempAddress[i] < 192) {
			name[position++] = tempAddress[i];
		}

		i++;
		if (hasPointer == 0) {
			length++;
		}
    }

    for (j = 0; j < strlen(name); j++) {
		if ((name[j + 1] < 48) && (name[j + 1] > 0)) {
			name[j] = '.';
		} else {
			name[j] = name[j + 1];
		}
    }

    if (!hasPointer) {
		length++;
    }

    return length;
}


//this will convert www.google.com to 3www6google3com 
void convertName(unsigned char *dns, unsigned char *host) {
    int lock = 0;
    strcat((char *) host, ".");

    for (int i = 0; i < (int) strlen((char *) host); i++) {
		if (host[i] == '.') {
			*dns++ = i - lock;
			for (; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++;
		}
    }
    *dns++ = '\0';
}


void lookupHost() {
	sendRequest();
	receiveResponse();
}

void sendRequest() {	
	s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);  //UDP packet for DNS queries
	sockaddr_in dest;
	dest.sin_family=AF_INET;
	dest.sin_port=htons(53); 
	dest.sin_addr.s_addr=inet_addr(dns_server);  

	unsigned char buf[1024],*qname;
	
	//Our query contains the DNS header and the question
	DNS_HEADER *dns   = NULL;
	QUESTION   *qinfo = NULL;

	//Initialize header
	dns=(DNS_HEADER*)&buf;
	dns->id = (unsigned short)htons(GetCurrentProcessId()); //Transaction id
	dns->qr = 0;			//This is a query
	dns->opcode = 0;		//This is a standard query
	dns->aa = 0;			//Not Authoritative
	dns->tc = 0;			//This message is not truncated
	dns->rd = recursive;    //Recursion Desired
	dns->ra = 0;			//Recursion not available! 
	dns->z  = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1);   //we have only 1 question
	dns->ans_count  = 0;
	dns->auth_count = 0;
	dns->add_count  = 0;

	//point to the question portion
	qname =(unsigned char*)&buf[sizeof(DNS_HEADER)];

	//Set host name, in the standard format 
	convertName(qname,host);
	//point to the end of the host 
	qinfo =(QUESTION*)&buf[sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
	
	//Set the query type 
	qinfo->qtype = htons(querytype); 
	//Set class 
	// You should always use 0x0001 representing Internet addresses.
	qinfo->qclass = htons(1); 

	//Send the packet

	//sizeof(DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(QUESTION)
	initialSize = 16 + (strlen((const char*)qname)+1); 
	if( sendto(s,(char*)buf,initialSize,0,(sockaddr*)&dest,sizeof(dest))==SOCKET_ERROR ) {
		printf("Could not send: %d  error",WSAGetLastError());
		exit(1);
	}
}


void receiveResponse() {
	memset(buffer, 0, 1024);

    int n = recvfrom(s, buffer, 1024, 0, NULL, NULL);
	if(n<0) {
		printf("Could not receive: %d  error",WSAGetLastError());
		exit(1);
	}

	DNS_ANSWER answers[20];
    DNS_HEADER res_header;

    memset(answers, 0, 20 * sizeof(DNS_ANSWER));
	memcpy(&res_header, &buffer, 12 );

    int i=0;

	//if any answers at all
	if (ntohs(res_header.ans_count) > 0) {
		 parseResponse(buffer, answers, initialSize, ntohs(res_header.ans_count));
		 char tempName[255];

		 //for each answer
		 for (int i = 0; i< ntohs(res_header.ans_count); i++) {
			 //MX RECORD
			
			 switch(answers[i].dns_type) {
				case T_MX: {
					extractName(answers[i].data + 2, tempName);
					int priority = 0;
					memcpy(&priority, answers[i].data, 2);
					priority = ntohs(priority);
					cout << "\nDomain name:" << answers[i].name << endl;
					cout << "Priority:" << priority << endl;
					cout << "MX Record:" << tempName << endl << endl;
					
					break;
				}
				case T_CNAME: {
					extractName(answers[i].data, tempName);
					cout << "\nDomain name:" << answers[i].name << endl;
					cout << "CNAME:" << tempName << endl; 					
					break;
				}
				case T_A: {

					//Display the ip address in dot notation

					int ip_address[4];
					for (int w=0;w<4;w++) {
						if (answers[i].data[w] < 0) {
							ip_address[w] = 256 + answers[i].data[w] ;
						}
						else {
							ip_address[w] = answers[i].data[w];
						}
					}

					cout << "\nDomain name:" << answers[i].name << endl;
					cout << "IP Address:";
					cout << ip_address[0] << "." << ip_address[1] << "." << ip_address[2] << "." << ip_address[3] << endl;

					break;
				} 
				case T_NS: {
					 extractName(answers[i].data, tempName);
					 cout << "\nDomain Name:" << answers[i].name << endl;
					 cout << "NS:" << tempName << endl;					 
					 break;
				} 
				case T_SOA: {
					int pos = 0;
					pos = extractName(answers[i].data, tempName);				
					
					char tempName2[255];
					pos += extractName(answers[i].data + pos, tempName2);								

					unsigned long serial = 0;
					unsigned long refresh = 0;
					unsigned int retry = 0;
					unsigned int expire = 0;
					unsigned int minimum =0;				

					memcpy(&serial,&answers[i].data[pos],4);
					serial = ntohl(serial);					
					memcpy(&refresh,&answers[i].data[pos + 4],4);
					refresh = ntohl(refresh);
					memcpy(&retry,&answers[i].data[pos + 8],4);
					retry = ntohl(retry);
					memcpy(&expire,&answers[i].data[pos + 12],4);
					expire = ntohl(expire);
					memcpy(&minimum,&answers[i].data[pos + 16],4);
					minimum = ntohl(minimum);

					cout << "\nDomain name:" << answers[i].name << endl;
					cout << "Primary name server:" << tempName << endl;
					cout << "Responsible authority's mailbox:" << tempName2 << endl;
					cout << "\nSerial number:" << serial << endl;
					cout << "Refresh interval:" << refresh << " seconds"<< endl;
					cout << "Retry interval:" << retry << " seconds"<< endl;
					cout << "Expiration limit:" << expire << " seconds"<< endl;
					cout << "Minimum TTL:" << minimum << " seconds"<< endl;
					break;
				}
				case T_PTR: {	
					//extractName(answers[i].data, tempName);
					cout << "\nDomain name:" << answers[i].name << endl;
					cout << "PTR:" << tempName << endl;		
					break;
				}
			} // switch
			 			 
		 } // for
	} 
	else { //no answers received
		
		cout << "\nAnswer count:" << ntohs(res_header.ans_count) << endl;
		cout << "Authority:" << ntohs(res_header.auth_count) << endl;
		cout << "Additional:" << ntohs(res_header.add_count) << endl;

		char nameservers[2][255][255];        
        memset(nameservers, 0, 2 * 255 * 255);
		int ppos = 0;

		if(ntohs(res_header.auth_count) > 0) {
			ppos = parseResponse(buffer, answers, initialSize, ntohs(res_header.auth_count));

			//Nameservers in the authority records section
			char tempName[255];
			for (int i = 0; i < ntohs(res_header.auth_count); i++) {
				extractName(answers[i].data, tempName);
				
				cout << "\nServer:" << answers[i].name << endl;
				cout << "\nNS:" << tempName << endl;
				sprintf(nameservers[0][i],"%s",tempName);
			}
		}

		if(ntohs(res_header.add_count)>0) {
			memset(answers, 0, 100 * sizeof(DNS_ANSWER));
			parseResponse(buffer, answers, initialSize + ppos, ntohs(res_header.add_count));

			//Additional records
			for (int i = 0; i< ntohs(res_header.add_count); i++) {
				if (answers[i].dns_type == T_A) {
					cout << "\nServer:" << answers[i].name << endl;
					cout << "IP:" << answers[i].data[0] << "." << answers[i].data[1] << "." << answers[i].data[2] <<"."<< answers[i].data[3] <<endl;
				}   
			}
		}
	}

}

//Chops the received buffer into the answer array
int parseResponse(char *buf, DNS_ANSWER *answers, int startSize, int blocks) {
	int position = 0;
    int i;
    int initialSize = startSize;

    for (i = 0; i< blocks; i++) {
        char tempName[255];
        unsigned short dataSize = 0;

        position += extractName(buf + position + initialSize, tempName);

        sprintf(answers[i].name, "%s", tempName);

        memcpy(&answers[i].dns_type, buf + position + initialSize, 2);
        answers[i].dns_type = ntohs(answers[i].dns_type);
        position += 2;

        memcpy(&answers[i].dns_class, buf + position + initialSize, 2);
        answers[i].dns_class = ntohs(answers[i].dns_class);
        position +=2;

        memcpy(&answers[i].ttl, buf + position + initialSize, 4);
        answers[i].ttl = ntohs(answers[i].ttl);
        position += 4;

        memcpy(&dataSize, buf + position + initialSize, 2);
        dataSize = ntohs(dataSize);
        position += 2;

        memcpy(&answers[i].data, buf + position + initialSize, dataSize);

        position += dataSize;
    }

    return position;
}