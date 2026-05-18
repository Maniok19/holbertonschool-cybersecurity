#!/bin/bash
dig +trace "$1" 2>&1 | grep -E '^[.;]' | head -1 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
