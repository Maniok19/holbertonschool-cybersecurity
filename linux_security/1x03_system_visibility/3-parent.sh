#!/bin/bash
ps -o ppid= -p "$PID" | tr -d ' '