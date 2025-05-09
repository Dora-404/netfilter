FROM golang:1.21-alpine

RUN apk add --no-cache libpcap-dev gcc

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY GeoLite2-Country.mmdb ./

RUN go build -o filter filter.go

CMD ["./filter"]
