FROM golang:1.26 AS build
WORKDIR /src
COPY . .
WORKDIR /src/services/issuerd
RUN CGO_ENABLED=0 go build -o /out/issuerd .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/issuerd /issuerd
ENTRYPOINT ["/issuerd"]
