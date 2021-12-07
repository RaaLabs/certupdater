# build stage
FROM golang:1.17.0-alpine AS build-env
RUN apk --no-cache add build-base git gcc

RUN mkdir -p /build
COPY ./certupdater /build/

WORKDIR /build/
RUN go version
RUN git checkout main && go build -o certupdater

# final stage
FROM alpine

RUN apk update && apk add curl && apk add nmap

WORKDIR /app
COPY --from=build-env /build/certupdater /app/

ENV DAEMON ""
ENV DOMAIN ""
ENV USER_FOLDER ""
ENV PROD ""

CMD ["ash","-c","/app/certupdater\
    -daemon=$DAEMON\
    -domain=$DOMAIN\
    -userFolder=$USER_FOLDER\
    -prod=$PROD\
    "]
