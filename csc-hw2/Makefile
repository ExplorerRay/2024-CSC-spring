CC = g++
CFLAGS = -Wall -Wextra -O2 -lpthread -lnetfilter_queue
PROGS = mitm_attack pharm_attack

all: $(PROGS)

utils.o: utils.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

mitm_attack: utils.o mitm_attack.cpp
	$(CC) $(CFLAGS) $^ -o $@

pharm_attack: utils.o pharm_attack.cpp
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(PROGS) *.o
	