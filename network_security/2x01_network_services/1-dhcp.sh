#!/bin/bash
grep -oP 'dhcp-server-identifier \K[0-9.]+' /var/lib/dhcp/dhclient.leases 2>/dev/null | tail -1
