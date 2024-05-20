PROGS = attacker_server crack_attack

.PHONY: clean all

all: $(PROGS)

# start from @ for no echo
crack_attack: crack.py virus.py /app/victim.dat
	@cp crack.py $@
	@chmod +x $@

attacker_server: server.py worm.py
	@cp server.py $@
	@chmod +x $@

clean:
	rm -f $(PROGS)
