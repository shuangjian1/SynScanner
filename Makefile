test: SynScanner.c
	rm -rf test
	sudo gcc  -o test SynScanner.c -lpthread
	sudo gcc -o syn syn_portscan.c -lpthread
clean:
	rm -rf test
