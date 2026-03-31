#!/bin/bash
echo "#!/bin/bash
cat /var/www/html/secret_config.php" > /usr/local/bin/audit-read-secret
chown root:root /usr/local/bin/audit-read-secret
chmod 755 /usr/local/bin/audit-read-secret

echo "$1 ALL=(root) NOPASSWD: /usr/local/bin/audit-read-secret" > "/etc/sudoers.d/$1_access"
chmod 440 /etc/sudoers.d/auditor_access