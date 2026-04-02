#!/bin/bash
if grep "PermitRootLogin no" $1;then
    echo "OK1"
else
    sed -i "s/.*PermitRootLogin.*/PermitRootLogin no/" $1
fi
if grep "PasswordAuthentication no" $1;then
    echo "OK2"
else
    sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/" $1
fi
if grep "PubkeyAuthentication yes" $1;then
    echo "OK3"
else
    sed -i "s/.*PubkeyAuthentication.*/PubkeyAuthentication yes/" $1
fi
if sshd -t;then
    echo "OKL"
fi