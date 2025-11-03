+++
date = '2025-11-03T12:00:00+08:00'
draft = false
title = '[2025]N1CTF WP for n1cat,eezzjs'
author='GSBP'
categories=["Java安全","CVE","N1CTF","WP"]

+++

## TL;DR

It's my first time to create challenges after i entered Nu1L Team. I'm glad to see so many hackers could solve my challenges though they have few problems(Such as in eezzjs, flag is in `/flag` instead of `/ffffflag` because my new attachment did not update on competition platform in time). Here are my expected solutions for these challenges

## eezzjs

In this challenges, your first work is to get a legal JWT that you could pass `authenticateJWT` middleware and use `/upload` to upload your file arbitrarily.

Actually it is easy to find this vuln. Beacuse when you try to debug locally, you could find information in this image

![image-20251103111304530](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20251103111304530.png)

When you run `npm audit`, you got the vuln is in sha.js,even it tells you the advisory of this vuln XD.

![image-20251103111339546](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20251103111339546.png)

The Principle of sha.js vuln is when you submit an Object  as `update()` 's arg, you could find `length` is assign by `data.length`,so this._len can be control that if data is an Object and it has a member named `length`

```
Hash.prototype.update = function (data, enc) {
  if (typeof data === 'string') {
    enc = enc || 'utf8'
    data = Buffer.from(data, enc)
  }

  var block = this._block
  var blockSize = this._blockSize
  var length = data.length
  var accum = this._len

  for (var offset = 0; offset < length;) {
    var assigned = accum % blockSize
    var remainder = Math.min(length - offset, blockSize - assigned)

    for (var i = 0; i < remainder; i++) {
      block[assigned + i] = data[offset + i]
    }

    accum += remainder
    offset += remainder

    if ((accum % blockSize) === 0) {
      this._update(block)
    }
  }

  this._len += length
  return this
}
```

where `this._len` equals to zero,its value always becomes the same.Then you could pass `authenticateJWT` and upload your file.

Next step，you should use `/upload` and `/` try to get RCE

As we all know,when ejs try to template a view in web.it would try to run this code 

```
  ...
  if (!opts.engines[this.ext]) {
    // load engine
    var mod = this.ext.slice(1)
    debug('require "%s"', mod)

    // default engine export
    var fn = require(mod).__express

    if (typeof fn !== 'function') {
      throw new Error('Module "' + mod + '" does not provide a view engine.')
    }
    ...
```

when you submit `?templ=abc.ddw`,it would try to require ddw modules. It gives us a chance to run arbitrary code.

![image-20251103121255718](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20251103121255718.png)

But we couldn't create dir or `js` file.How do we attack?

In [documents](https://nodejs.org/api/modules.html) we could know

> If the exact filename is not found, then Node.js will attempt to load the required filename with the added extensions: `.js`, `.json`, and finally `.node`. When loading a file that has a different extension (e.g. `.cjs`), its full name must be passed to `require()`, including its file extension (e.g. `require('./file.cjs')`).

So we could use `.node` file to finish our attack,[My exploit](https://github.com/Nu1LCTF/n1ctf-2025/tree/main/web/eezzjs/solution)

At last, i felt sorry for this challenge really has some issues,and there many unexpected solutions can solve this challenge that could use simply `../` or `./` bypass my ez waf haha.

## n1cat

n1cat is a gray challenge because if i provide full source code, the first step( `CVE-2025-55752`) is completely useless XD. In other words you could use this vulnerability to get full source code(maybe some libs was confused).

My attachment provide a Tomcat file `rewrite.config`,then you know `CVE-2025-55752` is a point of this challenge. You could try to read `web.xml`.

``` 
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <servlet>
        <servlet-name>welcomeServlet</servlet-name>
        <servlet-class>ctf.n1cat.welcomeServlet</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>welcomeServlet</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>
</web-app>

```

then you know `welcomeServlet` class path,you could use the same way to down it. The same applies to the`User` class and detect lib.

User.class

```
package ctf.n1cat;

import javax.naming.InitialContext;
import javax.naming.NamingException;

public class User {
    private String name;
    private String word;
    private String url;

    public User(){
    }
    public String getName() {
        return name;
    }
    public String getWord() {
        return word;
    }
    public void setWord(String password) {
        this.word = password;
    }

    public void setName(String name) throws NamingException {
        this.name = name;
    }
    public String getUrl() {
        return url;
    }
    public void setUrl(String url) {
        try{
            new InitialContext().lookup(url);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }
}

```

You could directly find a JNDI Injection vuln. Now first step is over.

The second step is try to use this vulnerability to get an rce.JDK version is 17,many ways of JNDI attack might not working.I uses RMI communicate deserialize(Communication between the RMI server and RMI client employs serialisation and deserialisation).About deserialize chains,we uses Jackson+SpringAOP to solve this (You could find `Jackson` dependence in `welcomeServlet`,`SpringAOP`dependence and version could use `CVE-2025-55752` to detect).

About this chains analysis,could see [this](https://fushuling.com/index.php/2025/08/21/%e9%ab%98%e7%89%88%e6%9c%acjdk%e4%b8%8b%e7%9a%84spring%e5%8e%9f%e7%94%9f%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e9%93%be/)

[My exploit](https://github.com/Nu1LCTF/n1ctf-2025/tree/main/web/n1cat/solution)

![image-20251103135843185](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20251103135843185.png)

## END

All challenges and solutions has uploaded on [GitHub]("https://github.com/Nu1LCTF/n1ctf-2025").Hope next time will be better