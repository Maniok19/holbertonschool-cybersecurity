#!/bin/bash
cp /etc/rsyslog.conf /etc/rsyslog.conf.backup

sed -i 's/^#module(load="imudp")$/module(load="imudp")/' /etc/rsyslog.conf
sed -i 's/^#input(type="imudp" port="514")$/input(type="imudp" port="514")/' /etc/rsyslog.conf
sed -i 's/^#module(load="imtcp")$/module(load="imtcp")/' /etc/rsyslog.conf
sed -i 's/^#input(type="imtcp" port="514")$/input(type="imtcp" port="514")/' /etc/rsyslog.conf

systemctl restart rsyslog