#!/bin/bash
ls /var/log/legacy_app/backups | while read zip;do
                gzip -d "/var/log/legacy_app/backups/$zip"
            done
ls /var/log/legacy_app/backups | while read og;do
                mv "/var/log/legacy_app/backups/$og" /var/log/legacy_app/
                echo "moved $og"
            done