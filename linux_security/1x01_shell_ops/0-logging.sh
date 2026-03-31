#!/bin/bash
exec 2>&1>$1 ; echo "Starting Task" ; echo "Doing Work" ; echo "Error: Work Failed"