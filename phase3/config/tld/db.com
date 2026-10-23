$TTL 3600
@       IN  SOA ns.com. admin.com. (
                2026102201 3600 900 604800 3600 )
@               IN  NS  ns.com.
ns.com.         IN  A   172.16.3.20
; ---- delegate example.com. to domain-ns ----
example.com.    IN  NS  ns.example.com.
ns.example.com. IN  A   172.16.3.30   ; glue