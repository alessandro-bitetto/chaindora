FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /out/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/app /app
ENTRYPOINT ["/app"]
