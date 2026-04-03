#!/bin/bash
useradd -m $1
usermod -L $1
USER_HOME="/home/$1"
mkdir "/home/$1/.ssh"
chmod 700 "/home/$1/.ssh"
echo "$2" > "/home/$1/.ssh/authorized_keys"
chmod 600 "/home/$1/.ssh/authorized_keys"
chown -R "$1:$1" "/home/$1/.ssh"
passwd -l "$1" | awk '{print "passwd: password expiry information changed."}'