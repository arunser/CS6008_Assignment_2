$TTL 3600
@       IN  SOA ns.example.com. admin.example.com. (
                2026102201 3600 900 604800 3600 )
@                IN  NS  ns.example.com.
ns.example.com.  IN  A   172.16.3.30
@                IN  A   172.16.1.20   ; example.com      -> webserver
www              IN  A   172.16.1.20   ; www.example.com  -> webserver