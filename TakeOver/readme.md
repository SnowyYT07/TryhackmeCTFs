## TakeOver CTF [Room](https://tryhackme.com/room/takeover)

First start the machine, when started grab the ip:
  - 10.10.61.139
  - Than lets add to ***/etc/hosts***

`sudo echo "10.10.61.139 futurevera.thm"`

When the /etc/hosts file is modificated lets start

1. use gobuster in the website:

`gobuster -w /path/to/wordlist -u futurevera.thm -m dns `

If all is right and the right wordlist was choose u will get an output like this

```
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dns
[+] Url/Domain   : futurevera.thm
[+] Threads      : 10
[+] Wordlist     : /path/to/wordlist
=====================================================
2023/01/25 18:29:08 Starting gobuster
=====================================================
Found: [hidden].futurevera.thm
Found: [hidden].futurevera.thm
Found: [hidden].futurevera.thm
=====================================================
2023/01/25 18:29:59 Finished
=====================================================
```
 
Lets add all in /etc/hosts

`sudo echo 10.10.61.139 [hidden].futurevera.thm`

**DO THAT TO ANY SUBDOMAIN**

 2. well, lets explore the blog
** we will discover that nothing interesting in the blog can be done, so, lets continue..**

 3. Same on portal.. we will get a page with this text

# xxxxxxx.futurevera.thm is only availiable via internal VPN

so lets continue, lets se the last subdomain

 4. Ohh something interesting (IF U USING CHROME)
```
This site can’t be reached
The webpage at https://xxxxxxx.futurevera.thm/ might be temporarily down or it may have moved permanently to a new web address.
ERR_SSL_KEY_USAGE_INCOMPATIBLE
```

So lets check the certificates... then we find...
| Subject Alt Names |
|-------------------|
|Dns Name: [secret].xxxxxx.futurevera.thm|

Entering there, we get the flag that is
flag{[SECRET]}


Well hope u guys enjoyed, thats it.
