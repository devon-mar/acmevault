build:
	go build -o acmevault .

integration:
	go test -coverpkg=./... -coverprofile=cover -tags=integration ./...

test:
	go test -coverprofile=cover ./...

