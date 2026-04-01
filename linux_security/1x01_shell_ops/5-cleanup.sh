#!/bin/bash
while read u; do
    if id $u &>/dev/null; then
        usermod --lock $u
        echo 'User ' $u 'locked'
    else
        echo 'User ' $u 'not found'
    fi
done < $1
