#!/bin/bash
if command -v "$1";then
echo "not instaled"
apt install "$1"
fi

if grep -q "minclass" "$2";then
    sed -i "s/.*minclass.*/minclass = 3/" "$2"
    echo 'modified minclass = 3'
    sed -i "s/.*minlen.*/minlen = 12/" "$2"
    echo 'modified minlen = 12'
else
    echo "minlen = 14" >> "$2"
    echo "minclass = 3" >> "$2"
fi