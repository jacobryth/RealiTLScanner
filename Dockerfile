FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
# Use -trimpath and -ldflags to reduce binary size
RUN go build -trimpath -ldflags "-s -w" -o RealiTLScanner .

FROM alpine:latest
# ca-certificates needed for TLS scanning, tzdata for consistent logging timestamps
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
ENTRYPOINT ["./RealiTLScanner"]
