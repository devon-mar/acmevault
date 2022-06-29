build:
	go build -o acmevault .

build-dns01all:
	go build -tags dns01 -o acmevault .

integration:
	go test -v -coverpkg=./... -coverprofile=cover -tags=integration ./...

test:
	go test -coverprofile=cover ./...

