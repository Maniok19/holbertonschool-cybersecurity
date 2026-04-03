#!/bin/bash
echo "$1 ALL=(ALL) /usr/bin/systemctl restart apache2, /usr/bin/journalctl" > "/etc/sudoers.d/junior"
chmod 440 "/etc/sudoers.d/junior"
visudo -c