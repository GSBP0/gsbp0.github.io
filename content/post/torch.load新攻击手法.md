+++

date = '2025-08-25T15:33:31+08:00'
draft = false
title = 'torch.load攻击新手法'
author='GSBP'
categories=["Pytorch"]

+++


## 前言

博客太久没更了，找点东西更更XD。这次看BlackHat ppt传出来了就看到了个有意思的Pytorch漏洞，在四五月份的时候已经有相关cve了(CVE-2025-32434)，效果是即使torch.load的参数weights_only=True，也能够成功的RCE,不过能否成功rce也要看情况，细节看下文

## 背景介绍

### weights_only

此参数更多的是限制在torch.load中pickle反序列化的能力，在torch早版本时期，利用pickle常规payload能够直接进行代码注入，命令执行等高危操作。于是官方推出此参数来保护用户的安全。在2.6.0版本中正式引入，并且此后版本的pickle.load此参数的默认值为True，即开启保护。

### TorchScript

TorchScript 是 PyTorch 提供的一种中间表示形式，它把原本依赖 Python 的动态图模型转换为可序列化、可优化、可独立运行的静态图。通过 torch.jit.trace 或 torch.jit.script 可以生成 TorchScript 模型，并保存为 .pt 文件，用于跨平台部署（如 C++、移动端）。它既保留了 PyTorch 的灵活性，又解决了性能优化和摆脱 Python 环境依赖的问题。

## 分析

​	为了方便理解，先拿出一个简单的demo出来

```python
import torch

class MyModule(torch.nn.Module):
    def __init__(self):
        super(MyModule, self).__init__()
        self.linear = torch.nn.Linear(10, 5)

    def forward(self):
        print(1)
        return torch.zeros(0)

module=MyModule()
sc=torch.jit.script(module)
sc.save("pytorch_model.bin")

newModule=torch.load("pytorch_model.bin",weights_only=True)
modins=newModule()
```

运行demo可以发现

![image-20250821150530808](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250821150530808.png)

此时我们可以通过这段demo理解到了一部份的漏洞实质，即这个漏洞并非只需要一个简单的load就能够进行攻击的，而是需要load后创造出来的对象进行一些方法调用才可以进行漏洞攻击，demo中使用的是对该对象进行实例化操作，该对象继承自nn.Module，在此过程中会自动的调用对应的forward方法，看下图代码

![image-20250821151243070](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250821151243070.png)

为了下一步的了解，我们理解到了forward方法能够被调用，那是否意味着我们能够写入任意代码呢，此时我们将forward方法改写成以下情况

```python
    def forward(self):
        eval("print(1)")
        return torch.zeros(0)
```

运行后产生下图报错

![image-20250821151646558](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250821151646558.png)

```
Python builtin <built-in function eval> is currently not supported in Torchscript
```

这里就了解到了我们的Torchscript，可以看出我们的eval方法并不被Torchscript所支持，因为eval没有对应的TorchScript操作符。所以现在我们再次理解到了漏洞的又一部份实质，即只有在Torchscript中存在操作符的方法才能够被编译成TorchScript使用

关于TorchScript的加载就存在于torch.load下的代码中

```python
def load():
    ......
    with _open_file_like(f, "rb") as opened_file:
        if _is_zipfile(opened_file):
            # The zipfile reader is going to advance the current file position.
            # If we want to actually tail call to torch.jit.load, we need to
            # reset back to the original position.
            orig_position = opened_file.tell()
            overall_storage = None
            with _open_zipfile_reader(opened_file) as opened_zipfile:
                if _is_torchscript_zip(opened_zipfile):
                    warnings.warn(
                        "'torch.load' received a zip file that looks like a TorchScript archive"
                        " dispatching to 'torch.jit.load' (call 'torch.jit.load' directly to"
                        " silence this warning)",
                        UserWarning,
                    )
                    opened_file.seek(orig_position)
                    return torch.jit.load(opened_file, map_location=map_location) #here
    .......
```

torch.jit.load将TorchScript的编译模型转换回了python中的应用模型，编译模型中的操作符也会被还原成相应的method，在原文中，作者找出两个可以利用的操作符(截自源ppt)

![image-20250825111626473](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250825111626473.png)

所对应的分别为以下两个方法(截自源ppt)

![image-20250825111759077](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250825111759077.png)

所以接下来的思路基本上就是从读写文件到rce的一个转换，作者写到的从任意文件写入到RCE的思路相信web🐶已司空见惯，这里不再多提。

这里还要说到的额外一点就是如果说有一个场景如下

```
import torch

class MyModule(torch.nn.Module):
    def __init__(self):
        super(MyModule, self).__init__()
        self.linear = torch.nn.Linear(10, 5)

    def forward(self):
        return torch.zeros(0)
    def xxx(self):
        print(1)
        return [("a", 1), ("b", 2)]

module=MyModule()
sc=torch.jit.script(module)
sc.save("demo/pytorch_model.bin")

newModule=torch.load("demo/pytorch_model.bin",weights_only=True)
newModule.xxx()
```

在load还原回模型后调用该实例的xxx方法，最后报错如下

![image-20250825112417714](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250825112417714.png)

我们只需要在forward方法中嵌入一段关于xxx()方法的调用就可以使其被主动编译存留在模型二进制文件中

![image-20250825112536810](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250825112536810.png)

这是因为在jit的方法编译过程中，是不会主动编译其他的非默认方法的

![image-20250825113351974](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250825113351974.png)

## 结尾

torch是当前python主流ai库里的常客，所以torch的安全也牵涉到了ai的安全，牵一发而动全身，所以对于torch的安全也是当前一个比较关注的问题了。