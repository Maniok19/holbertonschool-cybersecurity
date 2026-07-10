#!/bin/bash

nft add rule ip filter OUTPUT tcp dport {80,443} ip daddr 10.200.0.1 accept
nft add rule ip filter FORWARD ip saddr 10.200.0.0/24 tcp dport 80 drop
nft add rule ip filter FORWARD ip saddr 10.200.0.0/24 tcp dport 443 drop
nft add rule ip filter OUTPUT oif eth0 tcp dport {80,443} accept