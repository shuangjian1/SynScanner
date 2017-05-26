test: SynScanner.c
	sudo gcc  -Werror -Wall -o test SynScanner.c -lpthread
	sudo gcc -o syn syn_portscan.c -lpthread
clean:
	rm test
