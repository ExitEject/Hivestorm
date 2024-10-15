## one liner to enumerate some stuff
```sh
id && cat /etc/passwd && hostname && cat /etc/issue && cat /etc/os-release && uname -a && ps aux && ip a && nmcli dev show && find / -writable -type d 2>/dev/null && find / -perm -u=s -type f 2>/dev/null 
``` 
## find a string
```sh
find /home/finder -type f -exec grep -E 'replacethiswithwhatyouwant' {} \; 2>/dev/null
```
## check what's running
```sh
ps aux
top
w
who

```
## check active connections
```sh
nestat
ss -anp 
```
## check firewall settings
```sh
cat /etc/iptables/rules.v4 
```
## insepct for cronjobs
```sh
ls -lah /etc/cron* 
crontab -l
sudo crontab -l
```
## check writeable directories
```sh
find / -writable -type d 2>/dev/null 
```
## check available disks to mount, command to mount/umount
```sh
lsblk
mount 
```
## find SUID marked bins, remove SUID
```sh
find / -perm -u=s -type f 2>/dev/null
sudo find / -perm /2000 -type f -exec ls -l {} \; 2>/dev/null
sudo find / -perm /2000 -type d -exec ls -ld {} \; 2>/dev/null

chmod u-s /path/to/binary
chmod g-s /path/to/your/file
```
## find harmful software
```
ps aux | grep -E '(nc|netcat|bash|perl|python|ruby|sh|reverse)' | grep -v grep
sudo netstat -tulnp | grep -E '(:4444|:1337|:31337|:8888)'
find / -type f -perm /111 2>/dev/null | grep -E '\.(sh|py|pl|exe|bin|elf)$' > test.txt
find / -perm -4000 -type f 2>/dev/null | grep -v '^/bin' | grep -v '^/usr/bin'
sudo chkrootkit
```

## remove harmful software
```
sudo apt update && sudo apt install clamav clamav-daemon -y
sudo freshclam
sudo clamscan -r --bell -i /
clamscan -r --remove /path/to/directory
sudo rkhunter --check
```



## useful links
https://github.com/SystematicSkid/py-storm
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/linux-forensics
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis
