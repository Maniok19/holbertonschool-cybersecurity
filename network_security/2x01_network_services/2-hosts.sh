#!/bin/bash
grep "localhost" /etc/hosts | head -1 | awk '{print $1}'
