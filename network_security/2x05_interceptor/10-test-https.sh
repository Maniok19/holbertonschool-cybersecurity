#!/bin/bash
curl -x http://proxy_ip:3129 -o /dev/null -s -w "%{http_code}" https://malware.com