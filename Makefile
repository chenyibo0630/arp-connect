arp.o: arp.c arp.h
	gcc -c arp.c
arpDeceive.o: arpDeceive.c
	gcc -c arpDeceive.c
start: arp.o arpDeceive.o
	gcc arp.o arpDeceive.o -o start