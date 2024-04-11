CC = g++
CFLAGS = -Wall -Wextra -O2
PROGS = mitm_attack

all: $(PROGS)

# mitm_attack: mitm_attack.cpp
# 	$(CC) $(CFLAGS) -o $@ mitm_attack.cpp

utils.o: utils.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

mitm_attack: utils.o mitm_attack.cpp
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(PROGS) *.o