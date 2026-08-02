.PHONY: detach attach

PYTHON := $(shell which python3)

detach:
	sudo $(PYTHON) ebpf/detach.py $(network)

attach:
	make detach
	sudo $(PYTHON) ebpf/attach.py ${policy} $(network)
