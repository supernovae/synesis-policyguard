FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /policyguard ./cmd/policyguard

FROM alpine:3.19
RUN apk add --no-cache ca-certificates

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

COPY --from=builder /policyguard /usr/local/bin/policyguard
COPY configs/policies.yaml /etc/policyguard/policies.yaml

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/policyguard"]
