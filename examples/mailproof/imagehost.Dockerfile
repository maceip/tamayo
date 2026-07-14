FROM golang:1.26 AS build
WORKDIR /src
COPY . .
WORKDIR /src/examples/mailproof/imagehost
RUN CGO_ENABLED=0 go build -o /out/imagehost .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/imagehost /imagehost
ENTRYPOINT ["/imagehost"]
