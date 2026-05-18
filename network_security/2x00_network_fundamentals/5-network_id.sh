#!/bin/bash
IFS=. read -r a b c d <<< "$1"; IFS=. read -r e f g h <<< "$2"; echo "$((a&e)).$((b&f)).$((c&g)).$((d&h))"
