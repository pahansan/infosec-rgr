all: build run

build:
	go build -gcflags='all=-B -l=4' -ldflags='-w -s' -o zkp cmd/demo/main.go

run:
	GOGC=100000 ./main
