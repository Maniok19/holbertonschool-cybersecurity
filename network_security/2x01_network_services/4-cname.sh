#!/bin/bash
dig +short "$1" CNAME 2>/dev/null | head -1
