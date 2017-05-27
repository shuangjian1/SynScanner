test: SynScanner.c
	sudo gcc  -o test SynScanner.c -lpthread
clean:
	rm -rf test
