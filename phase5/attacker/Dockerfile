FROM alpine:3.22
RUN apk add --no-cache libpcap libpcap-dev build-base iproute2 tcpdump
COPY interceptor.c /src/interceptor.c
COPY walker.c /src/walker.c
RUN cc -O2 -Wall -o /usr/local/bin/interceptor /src/interceptor.c -lpcap \
 && cc -O2 -Wall -o /usr/local/bin/walker      /src/walker.c      -lpcap
CMD ["interceptor"]