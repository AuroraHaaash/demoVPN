#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <termios.h> 

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "127.0.0.1"

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"
#define CA_DIR "./ca_client"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

struct sockaddr_in peerAddr;

typedef struct threadArg {
    int tunFD;
    SSL *sslPtr;
} tunData;


int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}


SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	// mutual verify
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
        	printf("Failed to set the verify locations. \n");
        	exit(0);
    	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}


int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

int setupTCPClient(const char *hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	struct hostent *hp = gethostbyname(hostname);

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.8"); 
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));

	return sockfd;
}

/*-- Input Password Without ECHO --*/
void hiddenPassword(char *password) {
	struct termios initialSettings, newSettings;
	int singleChar;
	tcgetattr(STDIN_FILENO, &initialSettings);
	newSettings = initialSettings;
	//newSettings.c_lflag &= ~ICANON; //close to stop using like backspace, left, right, up, down an etc 
	newSettings.c_lflag &= ~ECHO;
    	tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);
    	fgets(password, 100, stdin); 
	password[strlen(password) - 1] = '\0';
	tcsetattr(STDIN_FILENO, TCSANOW, &initialSettings);
	return;
}


/*-- Listen To the Tunnel And Write To The SSL --*/
void listenTunnel(tunData *sslData) {
    	tunData *tempPtr = sslData;
	int len;
        char buff[BUFF_SIZE];

	

        bzero(buff, BUFF_SIZE);
        len = read(tempPtr->tunFD, buff, BUFF_SIZE);
	if (len > 19 && buff[0] == 0x45) {    
            	printf("Got a packet from TUN And Already Write To SSL\n");
		SSL_write(tempPtr->sslPtr, buff, len);
        }	
}


/*void tunSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}*/


/*-- Listen To the SSL And Write To The Tunnel --*/
void readFromSSl(tunData *sslData){
	tunData *tempPtr = sslData;
	char buf[BUFF_SIZE];
	int len = 0;
	
	printf("Got a packet from the tunnel\n");
	len = SSL_read(sslData->sslPtr, buf, sizeof(buf) - 1);
	buf[len] = '\0';
	write(sslData->tunFD, buf, len);
	printf("%s\n", buf);
}


/*void socketSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
	write(tunfd, buff, len);

}*/


int main(int argc, char *argv[])
{
	char hostName[100];
	int port = 0;
	char userName[100];
	char passWord[100];
	int tunfd;
	char ipFields[] = "";

	/*-- Input The HostName and Port --*/
	printf("Enter the HostName:       ");
	scanf("%s", hostName);
	printf("Enter the Server Port:    ");
	scanf("%d", &port);


	/*-- Input The UserName and Password --*/
	printf("Enter Your SSL UserName:  ");
	scanf("%s", userName);
	printf("Enter Your SSL Password:  ");
	//scanf("%s", passWord);
	getchar();
	hiddenPassword(passWord);


	/*------ TLS initialization ------*/
    	SSL *ssl = setupTLSClient(hostName);
    	printf("\nSet up TLS client successfully!\n");


	/*------ TCP connection ------*/
    	int sockfd = setupTCPClient(hostName, port);
    	printf("Set up TCP client successfully!\n");

	/*------ TLS handshake ------*/
    	SSL_set_fd(ssl, sockfd);
    	int err = SSL_connect(ssl);

    	CHK_SSL(err);
    	printf("SSL connection is successful\n");
    	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*------ Authenticating Client by user/passwd ------*/
    	SSL_write(ssl, userName, strlen(userName));  // username
    	SSL_write(ssl, passWord, strlen(passWord));  // password
    	//SSL_write(ssl, argv[1], strlen(argv[1])); 
	//SSL_write(ssl, '2', strlen('2')); 
	/*------ Wait For Login Resutl ------*/	
	char loginInfo[BUFF_SIZE];
	SSL_read(ssl, loginInfo, BUFF_SIZE);
	int loginFlag = atoi(loginInfo);
	if (loginFlag == 0){
		printf("Login Failed.\n");
		SSL_shutdown(ssl);
    		SSL_free(ssl);
    		close(sockfd);
		return 0;
	}
	else{
		printf("Login Successfully.\n\n");
		printf("Artificially Set Client IP(Last Fields): ");
		scanf("%s", ipFields);
		SSL_write(ssl, ipFields, strlen(ipFields) + 1);
	}
	/*----------------Send/Receive data --------------------*/
	char buf[9000];
	char sendBuf[200];
	tunfd = createTunDevice();

    	tunData sslData;
    	sslData.tunFD = tunfd;
    	sslData.sslPtr = ssl;
	
	/*-- Deal with The CMDS in C Code --*/
	char cmd[100];
    	sprintf(cmd, "sudo ifconfig tun0 192.168.53.%s/24 up && sudo route add -net 192.168.60.0/24 tun0", ipFields);
    	system(cmd);


	// Enter the main loop
	while (1) {
		struct tcp_info info; 
  		int len=sizeof(info); 
  		getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len);
  		if((info.tcpi_state==TCP_ESTABLISHED)){
			fd_set readFDSet;

			FD_ZERO(&readFDSet);
			FD_SET(sockfd, &readFDSet);
			FD_SET(tunfd, &readFDSet);
			select(5, &readFDSet, NULL, NULL, NULL);

			if (FD_ISSET(sockfd, &readFDSet))
				readFromSSl(&sslData);
			if (FD_ISSET(tunfd, &readFDSet))
				listenTunnel(&sslData);
		}
		else{
			printf("The Server ShutDown The Connection.\n");
			SSL_shutdown(ssl);
    			SSL_free(ssl);
    			close(sockfd);	
			return 0;	
		}
	}
}
