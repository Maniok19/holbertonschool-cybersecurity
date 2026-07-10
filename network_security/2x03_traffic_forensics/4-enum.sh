#!/bin/bash
tshark -r $1 -Y "http.response.code == 404" -T fields -e frame.number 2>/dev/null | wc -l