#!/bin/bash
lsof -iTCP:$1 -sTCP:LISTEN -Fn | grep '^n' | head -n1 | cut -c2- | xargs -r basename -P awk