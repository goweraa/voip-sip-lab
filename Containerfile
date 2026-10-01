FROM docker.io/library/alpine:3.22
RUN apk add --no-cache asterisk asterisk-sounds-en sipp pjsua tcpdump iproute2 iproute2-tc bash
