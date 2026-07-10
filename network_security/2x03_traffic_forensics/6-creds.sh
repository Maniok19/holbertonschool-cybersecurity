#!/bin/bash
tshark -r "$1" -Y "http" -T fields -e http.request.uri -e http.file_data | grep -oP '\b(?:password|pass|pwd)'