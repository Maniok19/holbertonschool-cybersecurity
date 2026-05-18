#!/bin/bash
tracepath -n "$1" 2>/dev/null | grep -c '^ *[0-9]\+:'