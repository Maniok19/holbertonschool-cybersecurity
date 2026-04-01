#!/bin/bash
until timeout 1 bash -c "cat < /dev/tcp/$1/80";do
echo 'Waiting...'
    sleep 1
done
echo 'Service UP!'