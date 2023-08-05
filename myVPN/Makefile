all: 
	gcc -o demoVPNClient demoVPNClient.c -lssl -lcrypto -w
	gcc -o demoVPNServer demoVPNServer.c -lssl -lcrypto -lpthread -lcrypt -w

clean: 
	rm -f demoVPNClient demoVPNServer 
	rm -f *~

