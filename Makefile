test: SynScanner.c
	gcc  -Werror -Wall -o test SynScanner.c -lpthread
clean:
	rm test
