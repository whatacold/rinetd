all: test_match test_sendrecv

test_match: test_match.c ../match.c
	gcc -o test_match test_match.c ../match.c

test_sendrecv: test_sendrecv.c
	gcc -o test_sendrecv test_sendrecv.c

clean:
	rm -f test_match test_sendrecv
