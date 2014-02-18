##### Makefile #####

# Chad Cahill
# eece 555
# Fall 2013

	
packets: packets.c
	gcc packets.c -Wall -o packets -lpcap
clean:
	rm packets

###################
