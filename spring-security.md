---
# Spring Security参考文档

Authors
Ben Alex , Luke Taylor , Rob Winch , Gunnar Hillert
4.2.3.RELEASE

Copyright © 2004-2015
Copies of this document may be made for your own use and for distribution to others, provided that you do not charge any fee for such copies and further provided that each copy contains this Copyright Notice, whether distributed in print or electronically.

---
# Ⅰ.前言
## 	1.入门
## 2.简介
## 3.Spring Security 4.2的新特性
## 4.参考指南和示例
## 5.Java配置
## 6.Security命名空间配置
## 7.示例应用
## 8.Spring Security社区
# II.架构与实施
## 9.技术概述
### 9.1 运行时环境
### 9.2 核心组件
#### 9.2.1 SecurityContextHolder, SecurityContext和Authentication对象
#### 9.2.2 UserDetailsService
#### 9.2.3 GrantedAuthority
#### 9.2.4 总结
### 9.3 认证
### 9.4 Web应用程序的认证
### 9.5 Spring Security的访问控制（授权）
### 9.6 本地化
## 10.核心服务
# III.测试
## 11.测试方法的安全性
## 12.Spring MVC测试模块的集成
# IV.Web应用程序安全
## 13.Security过滤器链
## 14.Security核心过滤器
## 15.Servlet API集成
## 16.Basic和Digest认证
## 17.Remember-Me认证
## 18.跨站请求伪造（CSRF）
## 19.CORS
## 20.Security Http响应头
## 21.Session管理
## 22.匿名认证
## 23.WebSocket安全
# V.授权
## 24.授权架构
## 25.安全对象的实现方式
## 26.基于表达式的访问控制

# VI.附加主题
## 27.Domain对象的安全（ACLs）
## 28.预认证的应用场景
## 29.LDAP认证
## 30.JSP标签库
## 31.Java认证和授权提供者（JAAS）
## 32.CAS认证
## 33.X.509认证
## 34.运行时认证替换
## 35.Spring Security Crypto模块
## 36.Spring Security对并发的支持
## 37.Spring MVC的集成
# VII. Spring Data集成Spring Security
## 38. Spring Data & Spring Security配置
## 39. @Query中应用Security表达式
# VIII. 附录
## 40.Security数据库设计
## 41.Security命名空间
## 42.Spring Security依赖
## 43.代理服务器配置
## 44.Spring Security FAQ
## 45.从3.x迁移到4.x

Spring Security是一款功能强大，可定制的身份验证和访问控制框架。实际上Spring Security也是基于Spring的应用程序的标准安全框架。

---
# Ⅰ.前言

# II.架构与实施
## 9.技术概述
### 9.1 运行时环境
Spring Security 3.0需要Java 5.0运行时环境或java 5.0以上版本。 由于Spring Security旨在以独立的方式运行，因此在Java运行时环境中无需任何特殊配置文件。 特别地，不需要配置特殊的Java认证和授权服务（JAAS）策略文件或将Spring Security放置到常见的类路径位置中。

同样，如果您正在使用EJB容器或Servlet容器，则无需在任何位置放置任何特殊的配置文件，也不需要在服务器类加载器中包含Spring Security。 所有必需的文件将包含在您的应用程序中。

此设计提供最大的部署灵活性，因为您可以简单地将目标构件（无论是JAR，WAR还是EAR）从一个系统复制到另一个系统，并立即运行。
### 9.2 核心组件
在Spring Security 3.0中，spring-security-core jar包中包含的内容被削减到最小化。 它不再包含与Web应用程序安全，LDAP以及命名空间配置相关的任何代码。 在核心模块中包含的Java类型代表了框架的基础构建模块，因此，如果你需要自定义一个命名空间配置，那么你就需要深入理解核心模块的代码，即使你不需要直接与核心模块进行交互。
#### 9.2.1 SecurityContextHolder, SecurityContext和Authentication对象
Spring Security中最基本的对象是SecurityContextHolder。SecurityContextHolder用来保存SecurityContext。SecurityContext中含有当前安全上下文的详细信息以及当前正在访问系统的认证主体的详细信息。默认情况下，SecurityContextHolder使用ThreadLocal来存储这些信息，这意味着在处于同一线程的方法中我们可以从ThreadLocal中获取到当前的SecurityContext，即使SecurityContext未作为参数显式传递给这些方法。如果希望在当前principal请求处理完毕后要清理这些线程，则使用ThreadLocal局部变量会是非常安全的。当然，Spring Security会自动处理这些问题，所以开发者无需担心这个问题。

在一些应用程序中，ThreadLocal并不一定适用，因为它们可能会用特定的方式运行线程。举个例子，一个Swing客户端可能希望所有在JVM中的线程使用相同的Security上下文。你可以配置SecurityContextHolder使得它在启动时以你希望的方式来保存上下文数据。对于一个独立的应用你可以使用SecurityContextHolder.MODE_GLOBAL策略。其他应用可能希望由安全线程与其衍生出来的线程具有统一的安全标识，则可以使用SecurityContextHolder.MODE_INHERITABLETHREADLOCAL策略。你可以通过两种方式改变默认的SecurityContextHolder.MODE_THREADLOCAL模式。第一种是设置一个系统属性，第二种方式是调用SecurityContextHolder的一个静态方法。大多数应用不需要修改这个默认的策略，如果需要修改，参考JavaDocs中的SecurityContextHolder获取更多信息。

##### 获取当前登陆用户的信息
在SecurityContextHolder中保存了当前与应用程序交互的认证主体的数据信息，Spring Security使用一个Authentication对象来保存和展示这些数据信息。你不需要自己手工创建一个Authentication对象，而且查询这个对象也相当的简单，你可以使用下面的代码（在你的应用的任意位置）获取当前认证用户的姓名信息：

```
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```
getContext()方法返回的对象是SecurityContext接口的实例，这就是保存在ThreadLocal局部变量中的对象。如下所示，Spring Security中的大多数身份验证机制将返回UserDetails对象作为认证主体的实例。
#### 9.2.2 UserDetailsService
在上述代码片段中，另一个需要注意的地方是可以从Authentication对象获取认证主体。认证主体(principal)是一个对象，大多数情况下可以转换成UserDetails对象。 UserDetails是Spring Security中的核心接口。它代表一个认证主体(principal)，可以根据应用程序特定的需求进行定制化的扩展。通常我们将UserDetails视为用户数据库与SecurityContextHolder之间的适配器。可以将UserDetails视为数据库中User主体的代言人，因此在实际程序中我们经常会将UserDetails转换为我们自定义的User主体对象，以便于调用特定于业务的方法（如getEmail()，getEmployeeNumber()等）。
(译者注：UserDetails接口是Spring Security提供的统一操作认证主体信息的接口，但是在我们实际开发中，我们通常实现此接口，并且根据实际的业务需求定义我们需要的属性)

你可能会感到奇怪，我什么时候需要提供一个UserDetails对象？用这个对象做什么？既然这个对象是声明性的，几乎不需要编写任何Java代码 - 那么它到底是怎么实现的呢？答案很简单，它是通过一个名为UserDetailsS​​ervice的特殊接口来实现期功能的。此接口上唯一的方法接受基于String的用户名参数，并返回UserDetails：

```
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```
在Spring Security中,这是加载用户信息的最常见方法，当需要用户信息时，UserDetails将在框架中发挥作用。

当用户认证成功后，UserDetails用于构建存储在SecurityContextHolder中的Authentication对象（下面会详细介绍）。 幸运的是，Spring Security为我们提供了一些UserDetailsService的实现，包括使用In-Memory（InMemoryDaoImpl）和另一个使用JDBC（JdbcDaoImpl）的实现。 大多数开发者倾向于自己编写UserDetailsService的实现类，但是实现方式往往只是基于现有的数据访问对象（DAO）之上，它代表了他们的employees, customers, 或者应用程序的其他users。 记住，通过SecurityContextHolder可以很方便地获取UserDetailsService返回的对象，关于如何获取，请参考9.2.1小节的内容。
> 一些开发者对于UserDetailsService接口会感到疑惑。 它纯粹是用户数据的DAO，只是将数据提供给框架内的其他组件。 特别地，它不进行用户认证，用户认证由AuthenticationManager完成的。 在大多数情况下，如果需要自定义身份验证过程，则直接实现AuthenticationProvider更有意义。

#### 9.2.3 GrantedAuthority
除了认证主体外，Authentication对象的另一个重要方法是getAuthorities()。此方法提供了一个GrantedAuthority对象的数组。GrantedAuthority对象，毫不奇怪，就是授权给认证主体的权限。这些权限通常是“ROLE”，例如ROLE_ADMINISTRATOR或ROLE_HR_SUPERVISOR。这些角色在后面的Web授权，方法授权和域对象授权时进行配置。 Spring Security的其他部分负责解释权限，并确定是否鉴权通过。 GrantedAuthority对象通常由UserDetailsS​​ervice来加载。

通常GrantedAuthority对象是应用程序范围的权限。它并不分配给指定的域对象。因此，您不可能将GrantedAuthority授权给编号为54的Employee对象，因为如果有成千上万的此类权限，您的内存很快将被耗尽（或至少导致应用程序花费很长时间来验证用户）。当然，Spring Security在设计时也考虑到了这种需求，但是推荐使用域对象来实现此类的权限校验。
#### 9.2.4 总结
这里做一个总结，到目前为止我们介绍过的Spring Security的主要组成部分是：

* SecurityContextHolder，提供对SecurityContext的访问。
* SecurityContext，用于保存身份验证和特定于请求的安全信息。
* Authentication，以Spring Security特定的方式来表示的认证主体。
* GrantedAuthority，用来反映授予认证主体的应用程序范围的权限。
* UserDetails，提供从应用程序的DAO或其他安全数据源构建Authentication对象所需的信息。
* UserDetailsService，通过传递基于字符串的用户名（或证书ID等）来创建UserDetails对象。

现在，您已经了解了这些重复使用的组件，接下来我们就仔细看看认证过程。

### 9.3 认证
### 9.4 Web应用程序的认证
### 9.5 Spring Security的访问控制（授权）
### 9.6 本地化