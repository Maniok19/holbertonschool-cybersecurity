#!/bin/bash

squid -k parse

if [ $? -eq 0 ]; then
    squid -k reconfigure
else
    echo "Configuration error. Squid not reloaded."
    exit 1
fi