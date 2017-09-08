LDFLAGS=-L/usr/local/opt/openssl/lib -lcrypto
CFLAGS=-I/usr/local/opt/openssl/include -std=c99 -Wall

send-bitcoin: bitcoin.o test.o
	$(CC) $(LDFLAGS) -o $@ $^

test: send-bitcoin
	./send-bitcoin test

all: send-bitcoin test

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
