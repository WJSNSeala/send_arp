send_arp : send_arp.c
	gcc -o send_arp -lpcap send_arp.c

clean:
	rm send_arp
