#!/bin/bash
grep "localhost" /etc/hosts | head -1 | awk '{printf "%s", $1}'
