BIN=overlayer
CC=gcc
export CC
build:
	go build -trimpath -buildvcs=false .
clean:
	rm $(BIN)
install: build
ifneq ($(shell id -u), 0)
	@echo "You must be root"
else
	cp $(BIN) /usr/local/bin/$(BIN)
	chmod +x /usr/local/bin/$(BIN)
endif
uninstall:
ifneq ($(shell id -u), 0)
	@echo "You must be root"
else
	rm -f /usr/local/bin/$(BIN)
endif

