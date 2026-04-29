FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
# Use -trimpath and -ldflags to reduce binary size
RUN go build -trimpath -ldflags "-s -w" -o RealiTLScanner .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
ENTRYPOINT ["./RealiTLScanner"]
