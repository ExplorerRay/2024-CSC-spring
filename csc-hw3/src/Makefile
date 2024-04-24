PY = python3
PROGS = attack_server crack_attack

.PHONY: clean all

all: $(PROGS)

# start from @ for no echo
crack_attack: crack.py victim.dat
	@cp crack.py $@
	@chmod +x $@

attack_server: server.py
	@cp server.py $@
	@chmod +x $@

clean:
	rm -f $(PROGS)
