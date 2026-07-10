#!/bin/bash
nft add rule ip filter INPUT tcp dport 3128 ip saddr 10.200.0.0/24 counter accept