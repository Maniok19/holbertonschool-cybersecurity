#!/bin/bash
awk -F: '$3 == 0{if ($1 != "root") print $1}' $1