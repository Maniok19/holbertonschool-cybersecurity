#!/bin/bash
#!/bin/bash
apt-get install -y squid && systemctl enable squid && cp /etc/squid/squid.conf /etc/squid/squid.conf.bak