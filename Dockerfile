FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /spa .

FROM scratch
COPY --from=build /spa /spa
ENTRYPOINT ["/spa"]
