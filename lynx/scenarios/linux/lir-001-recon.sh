# LIR-001: Linux reconnaissance and discovery (controlled lab run)
whoami
id
uname -a
hostname
lscpu | head -6
ip a | grep -E "inet |link/" | head -10
ip route
ss -tulpn 2>/dev/null | head -10
ps aux --no-headers | head -10
cat /etc/passwd
getent group sudo
sudo -l
find /home -maxdepth 2 -name "*.conf" 2>/dev/null | head -6
ping -c 1 127.0.0.1
for p in 22 80 443 8099; do timeout 0.3 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "port $p open"; done
