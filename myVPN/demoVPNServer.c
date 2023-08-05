#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <shadow.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"gyp-server-crt.pem"
#define KEYF	HOME"gyp-server-key.pem"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

struct sockaddr_in peerAddr;

/*typedef struct threadArg {
    int tunFD;
    SSL *sslPtr;
} tunData;
*/
typedef struct pipeData {
    char *fileName;
    SSL *ssl;
} pData;


SSL *setupTLSServer() {
	SSL_METHOD *meth;
    	SSL_CTX *ctx;
    	SSL *ssl;   

    	// Step 0: OpenSSL library initialization
    	// This step is no longer needed as of version 1.1.0.
    	SSL_library_init();
    	SSL_load_error_strings();
    	SSLeay_add_ssl_algorithms();

    	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

    	// Step 3: Create a new SSL structure for a connection
    	ssl = SSL_new(ctx);
    
    	return ssl;
}

int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
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

void *listenTUN(void *tunfd) {
    	int fd = *((int *)tunfd);
    	char buff[BUFF_SIZE];
    	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(fd, &readFDSet);
		select(5, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(fd, &readFDSet)){
        		int len = read(fd, buff, BUFF_SIZE);
			if (buff[0] == 0x45) {  // make sure that the data is a tcp packet 
				int connectionMark = (int)buff[19];
				char pipeFileName[100];
            			printf("Receive Data From Device TUN, IP.SRC = 192.168.53.%d\n", connectionMark);
            			sprintf(pipeFileName, "./pipe/192.168.53.%d", connectionMark);
            			int fp = open(pipeFileName, O_WRONLY);
            			if (fp == -1) {
                			printf("The IP-Corresponding Pipe File doesn't exist.\n");
            			} else {
                			write(fp, buff, len);
            			}
			}
		}
    	}
}

int login(char *user, char *passwd) {
    	struct spwd *pw;
    	char *epasswd;
    	pw = getspnam(user);
    	if (pw == NULL) {
        	printf("Password is NULL.\n");
        	return -1;
    	}

    	printf("Login name: %s\n", pw->sp_namp);
    	printf("Passwd    : %s\n", pw->sp_pwdp);

    	epasswd = crypt(passwd, pw->sp_pwdp);
    	if (strcmp(epasswd, pw->sp_pwdp)) {
        	printf("Incorrect password.\n");
        	return -1;
    	}
    	return 1;
}

void *readFromPipe(void *threadData) {
    	pData *ptrD = (pData*)threadData;
    	int pFD = open(ptrD->fileName, O_RDONLY);

    	char buff[BUFF_SIZE];
    	int len;
    	do {
        	len = read(pFD, buff, BUFF_SIZE);
		printf("Read Data From Pipe.\n");
       		SSL_write(ptrD->ssl, buff, len);
    	} while (len > 0);
    	//remove(ptrD->fileName);
}

void recvFromTunnel(SSL *ssl, int tunfd) {
    	int len;
    	do {
        	char buf[BUFF_SIZE];
        	len = SSL_read(ssl, buf, sizeof(buf) - 1); // block while nothing to read
		printf("Received SSL\n");
		printf("Read From Tunnel, Length: %d\n", len);
        	write(tunfd, buf, len);
        	buf[len] = '\0';
    	} while (len > 0);
    	printf("SSL shutdown.\n");
}

int main(int argc, char *argv[])
{
	int flag = 0;
	int err;
    	struct sockaddr_in sa_client;
    	size_t client_len;

    	/*------ TLS Initialization ------*/    
    	SSL *ssl = setupTLSServer();

    	/*------ TCP Connect ------*/
    	int listen_sock = setupTCPServer();
	fprintf(stderr, "listen_sock = %d\n", listen_sock);

    	/*-- Deal with The CMDS in C Code --*/
    	int tunfd = createTunDevice();
    	system("sudo ifconfig tun0 192.168.53.1/24 up");	

	/*-- Create Named Pipe --*/
    	system("rm -rf pipe");
    	mkdir("pipe", 666);
    	/*-- Create a Thread For listening to the TUN --*/
    	pthread_t TUNThread;
    	pthread_create(&TUNThread, NULL, listenTUN, (void *)&tunfd);
	
	while (1) {
		int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);

		fprintf(stderr, "sock = %d\n", sock);

		if (sock == -1) {
			fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}
		if (fork() == 0) {	// The child process
			close(listen_sock);

			SSL_set_fd(ssl, sock);
			int err = SSL_accept(ssl);
			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");

			/*-- Transformed Parameters' Receiver --*/
            		char usr[100];
			char pwd[100];
			char connectionMark[BUFF_SIZE];
			int sslDataLength = 0;
			/*-- Received Transformed Data --*/
			sslDataLength = SSL_read(ssl, usr, sizeof(usr) - 1);
            		usr[sslDataLength] = '\0';

			sslDataLength = SSL_read(ssl, pwd, sizeof(pwd) - 1);
            		pwd[sslDataLength] = '\0';
			

			/*-- Identification Authentication --*/
			int logStat = login(usr, pwd);

			if (logStat == 1) {
				char loginFlag[] = "1";
                		printf("Login Successfully!");
				SSL_write(ssl, loginFlag, strlen(loginFlag) + 1);
				
				sslDataLength = SSL_read(ssl, connectionMark, sizeof(connectionMark) - 1);
            			connectionMark[sslDataLength] = '\0';
                		// check IP and create pipe file
                		char pf[10];
                		sprintf(pf, "./pipe/192.168.53.%s", connectionMark);
                		if (mkfifo(pf, 0666) == -1) {
                    			printf("Current IP is occupied.\n");
                		} 
				else {
					printf("Distributed IP: 192.168.53.%s\n\n",  connectionMark);
					pData dataForPipe;
                    			pthread_t pipeThread;

                    			dataForPipe.fileName = pf;
                    			dataForPipe.ssl = ssl;

                    			pthread_create(&pipeThread, NULL, readFromPipe, (void *)&dataForPipe);
                    			recvFromTunnel(ssl, tunfd);
                    			pthread_cancel(pipeThread);
					printf("Finished Reading from Pipe, Close the Connection and Remove Pipe.\n");
                    			remove(pf);
                		}
            		} 
			else {
				char loginFlag[] = "0";
                		printf("Login Failed.\n");
				SSL_write(ssl, loginFlag, strlen(loginFlag) + 1);
				SSL_shutdown(ssl);
            			SSL_free(ssl);
            			close(sock);
            			printf("Socket Closed.\n\n");
            			return 0;
            		}
			SSL_shutdown(ssl);
            		SSL_free(ssl);
            		close(sock);
            		printf("Socket Closed. Client IP: 192.168.53.%s\n\n", connectionMark);
            		return 0;

		} else {	// The parent process
			close(sock);
		}
	}	
}
