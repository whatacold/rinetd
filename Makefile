CFLAGS=-DLINUX -DDEBUG -g

rinetd: rinetd.o match.o log.o conn.o
	gcc rinetd.o match.o log.o conn.o -o rinetd

install: rinetd
	install -m 700 rinetd /usr/sbin
	install -m 644 rinetd.8 /usr/man/man8

clean:
	rm -f rinetd *.o
