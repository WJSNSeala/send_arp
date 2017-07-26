send_arp : send_arp.c
	gcc -o send_arp -W -Wall -lpcap send_arp.c

clean:
	rm send_arp
