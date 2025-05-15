+++
date = '2025-05-15T16:57:31+08:00'
title = 'K8slanparty WP'
draft = false
author='GSBP'
categories=["云安全","WP"]
+++

---
## DNSing with the stars

---

> You have shell access to compromised a Kubernetes pod at the bottom of this page, and your next objective is to compromise other internal services further.
>
> As a warmup, utilize [DNS scanning](https://thegreycorner.com/2023/12/13/kubernetes-internal-service-discovery.html#kubernetes-dns-to-the-partial-rescue) to uncover hidden internal services and obtain the flag. We have "loaded your machine with [dnscan](https://gist.github.com/nirohfeld/c596898673ead369cb8992d97a1c764e) to ease this process for further challenges.
>
> All the flags in the challenge follow the same format: wiz_k8s_lan_party{*}

---

根据题目信息可以知道是利用dnscan寻找k8s主机

通过env可以发现k8s的一些信息，比如service主机地址

![image-20250514172712063](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514172712063.png)

所以我们以service ip来找其cidr块中的其他主机就行了

![image-20250514172902917](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514172902917.png)

找到dns为**getflag-service.k8s-lan-party.svc.cluster.local.**

接下来curl一下就好了

![image-20250514172938267](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514172938267.png)

## Hello?

---

>Sometimes, it seems we are the only ones around, but we should always be on guard against invisible [sidecars](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) reporting sensitive secrets.

---

Sidecar，指的是一种特殊的随着容器开启而启动的__init__容器

Sidecar具有独立的生命周期。它们可以独立于应用容器启动、停止和重启。 这意味着你可以更新、扩展或维护Sidecar容器，而不影响主应用。

变更Sidecar的镜像不会导致 Pod 重启，但会触发容器重启。



这一题的Sidecar的作用是不停的往主容器发数据，这些数据就有flag（别问为什么，问就是ctf靠猜

ifconfig找到网卡名

![image-20250514180022376](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514180022376.png)

tcpdump抓流量

```
tcpdump -ins-bbf712 -XX -vvv -nn
```

![image-20250514180103370](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514180103370.png)

## Exposed File Share

---

The targeted big corp utilizes outdated, yet cloud-supported technology for data storage in production. But oh my, this technology was introduced in an era when access control was only network-based 🤦‍️.

---

这题的问题主要是出在一个nfs系统上,在浏览文件时，可以看见根目录下多了个efs文件夹，flag.txt都在里面，但是没权限读

![image-20250514183942750](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514183942750.png)

根据题目里说的过期的储存架构，可以合理的看一眼mount

![image-20250514184134250](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514184134250.png)

确实是一个efs服务，由于efs的信任机制，我们可以使用nfs-cat和nfs-ls的同时自设uid和gid,version实现越权读取

下面是GPT老师的解释

>这是个非常好的问题。NFS 和 EFS 允许客户端“自报家门”（即客户端指定 UID/GID）听起来确实危险，但它背后有明确的**历史原因**和**设计取舍**。下面从多个角度解释为什么会有这种设计：
>
>------
>
>## 🧱 1. **历史背景：NFS 是为信任环境设计的**
>
>NFS（Network File System）最初由 Sun Microsystems 在 1980 年代设计，那时的目标是：
>
>- 在一个局域网（LAN）中的可信主机之间共享文件。
>- 所有主机被认为是受信的，用户账户和 UID 是统一的。
>- 系统管理员控制整个网络，因此不需要“验证”每个 UID。
>
>因此，NFS 协议从一开始就有个**基本假设**：
>
>> “客户端发送过来的 UID/GID 是可信的。”
>
>这对性能和设计来说是很简单的方案，但不适合不可信网络。
>
>------
>
>## ☁️ 2. **EFS 基于 NFSv4 协议，为兼容而保留此行为**
>
>AWS EFS 是构建在 **NFSv4** 协议之上的托管服务。为了兼容现有生态和操作系统挂载行为，EFS 保留了 NFS 的传统机制：
>
>- 客户端控制 UID/GID。
>- 服务端只根据 UID 来判断访问权限。
>
>这使得你可以**无缝把现有 Linux/NFS 系统迁移到 EFS**，不用修改太多逻辑。



这题我们用不了他的域名[fs-0779524599b7d5e7e.efs.us-west-1.amazonaws.com]来访问，好像是没有dns服务，这里用ip就好了，也在上面的红框框里

(这里的/要双写)

![image-20250514184434276](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514184434276.png)

## The Beauty and The Ist

---

> Apparently, new service mesh technologies hold unique appeal for ultra-elite users (root users). Don't abuse this power; use it responsibly and with caution.

---

这题考了个istio的规则绕过

根据hint1给的document可以得到下面的iptables

![image-20250514211427991](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514211427991.png)

一开始我还在想怎么获取环境里istio的iptables,没想到的是作者给这个hint就是把iptables给我们（似乎是默认配置啥的

我们可以在iptables里看到

```
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -m owner --uid-owner 1337 -j ISTIO_IN_REDIRECT
-A ISTIO_OUTPUT -o lo -m owner ! --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -m owner --gid-owner 1337 -j ISTIO_IN_REDIRECT
-A ISTIO_OUTPUT -o lo -m owner ! --gid-owner 1337 -j RETURN
```

反正就是uid是1337的话就通过

istio的服务可以dnscan找到

看一下/etc/passwd，就找到了1337的istio

![image-20250514211639206](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250514211639206.png)

## Who will guard the guardians?

---

> Where pods are being mutated by a foreign regime, one could abuse its bureaucracy and leak sensitive information from the [administrative](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request) services.

---

dnscan发现kyverno服务

![image-20250515161846130](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250515161846130.png)

kyverno是k8s的一个策略管理应用，这题我们的策略如下

```
apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: apply-flag-to-env
  namespace: sensitive-ns
spec:
  rules:
    - name: inject-env-vars
      match:
        resources:
          kinds:
            - Pod
      mutate:
        patchStrategicMerge:
          spec:
            containers:
              - name: "*"
                env:
                  - name: FLAG
                    value: "{flag}"
```

kyverno会把创建在namespace=sensitive-ns的containers都添加一个flag环境变量

这里调用了kyverno的mutate接口，这个接口是 AdmissionReview的接口，需要我们发送对应的内容

这里用到了kube-review来生成

写一个yaml，用于创建一个新Containers在sensitive-ns下

```
apiVersion: v1
kind: Pod
metadata:
  name: sensitive-pod
  namespace: sensitive-ns
spec:
  containers:
  - name: nginx
    image: nginx:latest
```

然后生成json，再搭个web服务传给攻击机

![image-20250515165235511](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250515165235511.png)

![image-20250515165306638](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250515165306638.png)

patch内容被base64加密了，根据kyverno的政策，可以判断patch就有他添加的env内容，即flag

​	![image-20250515165408567](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250515165408567.png)



## 结尾

头一次打k8s的靶场，感觉东西很多，要了解的东西也有很多，网上有相关资料但不是特别丰富，用ai找一些解释就很方便，不过这里还没有让我们用kubectl这些东西，只能说入门了解还可以
