test: SynScanner.c
	sudo gcc  -Werror -Wall -o test SynScanner.c -lpthread
clean:
	rm test
