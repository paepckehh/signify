PROJECT=$(shell basename $(CURDIR))

all: 
	go build

deps: 
	rm go.mod 
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	gofmt -w -s .
	staticcheck
