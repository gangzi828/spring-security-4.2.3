
# Spring Security参考文档

Authors
Ben Alex , Luke Taylor , Rob Winch , Gunnar Hillert
4.2.3.RELEASE

Copyright © 2004-2015
Copies of this document may be made for your own use and for distribution to others, provided that you do not charge any fee for such copies and further provided that each copy contains this Copyright Notice, whether distributed in print or electronically.

# 关于本翻译 
### 翻译者：gangzi828

### 联系方式：QQ-1139872666

译者简介：本人是一个对新技术的热爱者，平时喜欢翻译一些国外技术资料，是开源技术的热衷者。现就职于杭州一家网络与信息安全公司，负责公司项目组的java开发和android开发。

#### 声明：这个本人业余时间的翻译作品，任何组织和个人不得以商业利益为目的进行非法传播。如有翻译不正确之处，请多多指正，喷子请远离。若您对本翻译计划感兴趣，欢迎您的加入，共同为开源界做贡献。如果您觉得该文档对您有帮助，不妨打赏兄弟一杯咖啡，以示鼓励。
<center>![](me.png)</center>

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
### 8.1 问题跟踪
### 8.2 参与Spring Security项目
### 8.3 更多信息
# II.架构与实施
## 9.技术概述
### 9.1 运行时环境
### 9.2 核心组件
#### 9.2.1 SecurityContextHolder, SecurityContext和Authentication对象
#### 9.2.2 UserDetailsService
#### 9.2.3 GrantedAuthority
#### 9.2.4 总结
### 9.3 认证
#### 9.3.1 Spring Security的认证过程?
#### 9.3.2 直接设置SecurityContextHolder的内容
### 9.4 Web应用程序的认证
#### 9.4.1 ExceptionTranslationFilter
#### 9.4.2 AuthenticationEntryPoint
#### 9.4.3 认证机制
#### 9.4.4 存储SecurityContext
### 9.5 Spring Security的访问控制（授权）
#### 9.5.1 Security和AOP Advice
#### 9.5.2 受保护对象和AbstractSecurityInterceptor
### 9.6 本地化
## 10.核心服务
### 10.1 AuthenticationManager, ProviderManager和AuthenticationProvider
#### 10.1.1 认证成功时清楚凭证
#### 10.1.2 DaoAuthenticationProvider
### 10.2 UserDetailsService实现
#### 10.2.1 In-Memory Authentication
#### 10.2.2 JdbcDaoImpl
### 10.3 密码编码
#### 10.3.1 什么是hash
#### 10.3.2 加盐后Hash
### 10.4 Jackson支持
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
### 18.1 什么是CSRF
### 18.2 同步器令牌模式
### 18.3 何时启用CSRF攻击防御
#### 18.3.1 CSRF防御和JSON
#### 18.3.2 CSRF和无状态浏览器应用程序
### 18.4 启用Spring Security CSRF防护
#### 18.4.1 恰当的HTTP请求方法
#### 18.4.2 配置CSRF保护
#### 18.4.3 包含CSRF令牌
### 18.5 CSRF警告
#### 18.5.1 Token过期
#### 18.5.2 登陆
#### 18.5.3 退出
#### 18.5.4 Multipart (文件上传)
#### 18.5.5 HiddenHttpMethodFilter
### 18.6 覆盖默认值
## 19.CORS
## 20.Security Http响应头
## 21.Session管理
### 21.1 SessionManagementFilter
### 21.2 SessionAuthenticationStrategy
### 21.3 并发Session控制
#### 21.3.1 查询当前登陆用户及其会话的SessionRegistry
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
## 8.Spring Security社区
### 8.1 问题跟踪
Spring Security使用JIRA来管理bug报告和增强请求。 如果您发现bug，请使用JIRA登录报告。 不要在支持论坛，邮件列表或通过电子邮件将bug发送给项目的开发人员。 这种方法不正规，我们更喜欢使用正规的方式来管理bug。

如果可能，在您的bug报告中，请提供一个JUnit测试，证明任何不正确的行为。 或者，更好的是提供一个修正问题的修补程序。 同样地，尽管我们只接受增强请求，但如果您包含相应的单元测试，欢迎更新增强功能。 这对于确保项目测试覆盖率是必要的。

您可以访问[https://github.com/spring-projects/spring-security/issues](https://github.com/spring-projects/spring-security/issues)上的问题跟踪器。

### 8.2 参与Spring Security项目
我们欢迎您参与Spring Security项目。 有很多方式可以为该项目做出贡献，包括阅读论坛和回答别人的问题，编写新的代码，改进现有的代码，协助文档编制，开发示例或教程，或者只是提出建议。
### 8.3 更多信息
欢迎提出有关Spring Security的问题和意见。 您可以使用Spring Over Stack网站[http://spring.io/questions](http://spring.io/questions)与框架的其他用户讨论Spring Security。 请记住使用JIRA进行bug报告，如上所述。
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
Spring Security可以与其他的认证环境集成。 尽管我们建议使用Spring Security进行身份验证，但Spring Security仍然支持与现有的容器管理身份验证集成 - 与您自己的专有身份验证系统集成在一起。
#### 9.3.1 Spring Security的认证过程?
让我们看一个大家都熟悉的标准认证场景。

1.用户使用username和password登录

2.系统验证这个username的password是否是正确的

3.假设第二步验证成功，获取该用户的上下文信息（如他的角色列表）

4.围绕该用户建立安全上下文（security context）

5.用户继续执行一些由访问控制机制保护的操作，该访问控制机制根据当前的安全上下文信息检查针对该操作的所需权限。

前三个步骤构成了身份认证过程，因此，我们将看看Spring Security是如何进行身份认证的。

1. 获取username和password并将其组合为UsernamePasswordAuthenticationToken（我们前面看到的Authentication接口的一个实例）的一个实例。
2. UsernamePasswordAuthenticationToken被传递给AuthenticationManager的实例以进行验证。
3. AuthenticationManager在成功认证时返回完整的Authentication实例。
4. 安全上下文(SecurityContext)通过调用SecurityContextHolder.getContext().setAuthentication（...）方法创建的，调用时需要传入返回的Authentication对象。

通过上面四个步骤，用户已经认证成功。 我们来看一些示例代码。

```
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticationExample {
private static AuthenticationManager am = new SampleAuthenticationManager();

public static void main(String[] args) throws Exception {
	BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

	while(true) {
	System.out.println("Please enter your username:");
	String name = in.readLine();
	System.out.println("Please enter your password:");
	String password = in.readLine();
	try {
		Authentication request = new UsernamePasswordAuthenticationToken(name, password);
		Authentication result = am.authenticate(request);
		SecurityContextHolder.getContext().setAuthentication(result);
		break;
	} catch(AuthenticationException e) {
		System.out.println("Authentication failed: " + e.getMessage());
	}
	}
	System.out.println("Successfully authenticated. Security context contains: " +
			SecurityContextHolder.getContext().getAuthentication());
}
}

class SampleAuthenticationManager implements AuthenticationManager {
static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();

static {
	AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
}

public Authentication authenticate(Authentication auth) throws AuthenticationException {
	if (auth.getName().equals(auth.getCredentials())) {
	return new UsernamePasswordAuthenticationToken(auth.getName(),
		auth.getCredentials(), AUTHORITIES);
	}
	throw new BadCredentialsException("Bad Credentials");
}
}
```
这里我们写了一个简单的认证程序，要求用户输入用户名和密码，并执行上述认证过程。 我们在这里实现的AuthenticationManager将验证用户名和密码相同的用户。 它为每个用户分配一个角色。 上面的输出将是：

```
Please enter your username:
bob
Please enter your password:
password
Authentication failed: Bad Credentials
Please enter your username:
bob
Please enter your password:
bob
Successfully authenticated. Security context contains: \
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@441d0230: \
Principal: bob; Password: [PROTECTED]; \
Authenticated: true; Details: null; \
Granted Authorities: ROLE_USER
```
请注意，在实际开发中，您通常不需要编写这样的代码。 认证过程通常在Spring Security内部进行，例如在Web认证过滤器中。 我们之所以提供上面的示例代码，是为了简单阐述Spring Security的身份认证过程。 当SecurityContextHolder包含完整的Authentication对象时，表明用户身份验证通过。

#### 9.3.2 直接设置SecurityContextHolder的内容

事实上，Spring Security不关心如何将Authentication对象放在SecurityContextHolder中。唯一的要求是SecurityContextHolder要包含一个Authentication对象，Authentication对象代表AbstractSecurityInterceptor（我们将在后面看到更多信息）需要授权的主体。

您可以（并且许多用户）自定义身份认证过滤器或MVC控制器，以便于与Spring Security的身份验证系统进行交互。例如，您可能正在使用容器管理身份验证，这使得当前用户可以从ThreadLocal或JNDI位置获得。或者您工作的公司拥有传统专有认证系统，这种认证系统是一种企业“标准”，您几乎无法控制。在这样的情况下，很容易让Spring Security工作，并且仍然提供授权功能。所有您需要做的是编写从指定位置读取第三方用户信息的过滤器（或其他能实现相同功能的等价组件），构建一个特定于Spring Security的Authentication对象，并将其放入SecurityContextHolder中。在这种情况下，您还需要考虑通常由内置身份验证基础设施自动处理的内容。例如，在将响应写入客户端之前，您可能需要先占先创建一个HTTP Session来缓存请求之间的上下文：响应提交后无法创建会话。

如果您想知道AuthenticationManager是如何实现的，那么我们将在核心服务章节中看到。
### 9.4 Web应用程序的认证

现在让我们来探讨在Web应用程序中使用Spring Security的情况（不启用web.xml安全性）。用户如何认证和建立安全上下文的呢？

考虑一个典型的Web应用程序的认证过程：

1. 您访问主页，然后单击链接。
2. 请求发送到服务器，并且服务器决定您已请求受保护的资源。
3. 由于您目前没有身份验证，服务器会返回一个表明您必须验证的响应。响应将是HTTP响应代码或重定向到特定网页。
4. 根据身份验证机制，您的浏览器将重定向到特定网页，以便您填写表单，或者浏览器将以某种方式检索您的身份（通过BASIC身份验证对话框，Cookie，X.509证书等） ）。
5. 浏览器将向服务器发送回应。这将是一个包含您填写的表单内容的HTTP POST，或包含您的身份验证详细信息的HTTP头。
6. 接下来，服务器将决定所提供的凭证是否有效。如果它们有效，将进行下一步。如果它们无效，通常您的浏览器将被要求再次尝试（所以您将返回到上面的第二步）。
7. 将重试身份验证过程的原始请求。希望您已通过足够授权的权限验证访问受保护的资源。如果您有足够的访问权限，则请求将成功。否则，您将收到一个HTTP错误代码403，这意味着“禁止”。

Spring Security内置不同的类来负责上述大部分步骤的实现。这些类主要包括（根据它们的调用顺序）ExceptionTranslationFilter，AuthenticationEntryPoint和“认证机制”，认证机制负责调用我们上一节中提到的AuthenticationManager。
#### 9.4.1 ExceptionTranslationFilter
ExceptionTranslationFilter是一个Spring Security过滤器，负责检测Spring Security抛出的任何异常。 这些异常通常将由负责授权服务的主要提供者AbstractSecurityInterceptor抛出。 我们将在下一节中讨论AbstractSecurityInterceptor，但是现在我们只需要知道AbstractSecurityInterceptor会抛出Java异常即可，无需关心抛出的是HTTP异常还是主体的认证异常。 相反，ExceptionTranslationFilter负责解析AbstractSecurityInterceptor抛出的具体异常，例如返回错误代码403（如果主体已经通过身份验证，但缺乏足够的访问权限，如上面的第七步），或启动AuthenticationEntryPoint（如果主体未被验证， 如上面的第三步）。
#### 9.4.2 AuthenticationEntryPoint
AuthenticationEntryPoint负责上述列表中的第三步。 我们知道，每个Web应用程序都将有一个默认的身份验证策略（可以像Spring Security中几乎所有的配置一样配置）。 每个主要的认证系统都有自己的AuthenticationEntryPoint实现，例如步骤3中描述的BASIC认证、X.509等。
#### 9.4.3 认证机制
一旦您的浏览器提交您的身份认证凭据（以HTTP表单形式或者HTTP请求头的形式），服务器上需要“收集”这些身份验证的详细信息。这对应上面列出的第六步。在Spring Security中，我们有一个特殊名称，用于从用户代理（通常是Web浏览器）收集认证详细信息，将其称为“身份验证机制”。示例程序是基于表单登录和基本身份验证的机制。一旦从用户代理收集了认证详细信息，就构建了一个认证“请求”对象，然后呈现给AuthenticationManager。

认证机制接收到包含完整信息的认证对象后，会认为该请求有效，将包含详细认证信息的认证主体放入SecurityContextHolder，并引起原始请求重试（上述第七步）。另一方面，如果AuthenticationManager拒绝了请求，则认证机制将要求用户代理重试（返回到上述的第二步）。
#### 9.4.4 存储SecurityContext
根据应用程序的类型，可能需要有一个策略来存储用户操作之间的SecurityContext。在典型的Web应用程序中，用户登录一次，在随后的请求中由其SessionID进行认证标识。服务器将认证主体信息缓存在Session中。在Spring Security中，SecurityContextPersistenceFilter负责存储SecurityContext，默认情况下，它将SecurityContext作为HTTP请求之间的HttpSession属性存储。它将每个请求的上下文恢复到SecurityContextHolder，并且至关重要的是，在请求完成时清除SecurityContextHolder。为了安全起见，您不应该直接与HttpSession交互。而且也完全没有必要直接与HttpSession交互——使用SecurityContextHolder来间接与HttpSession交互。

许多其他类型的应用程序（例如，无状态RESTful Web服务）不使用HTTP会话，并将在每个请求上重新进行身份验证。但是，SecurityContextPersistenceFilter包含在链中仍然很重要，以确保每个请求后SecurityContextHolder被清除。

> 在单个会话中接收并发请求的应用程序中，相同的SecurityContext实例将在线程之间共享。 即使正在使用ThreadLocal，它是从HttpSession为每个线程检索的实例。 如果您希望临时更改线程正在运行的上下文，则会产生影响。 如果您只是使用SecurityContextHolder.getContext()，并在返回的上下文对象上调用setAuthentication（anAuthentication），则认证对象将在共享相同SecurityContext实例的所有并发线程中更改。 您可以自定义SecurityContextPersistenceFilter的行为，为每个请求创建一个全新的SecurityContext，从而防止一个线程中的更改影响另一个线程。 或者，您可以在临时更改上下文的位置创建一个新的实例。 方法SecurityContextHolder.createEmptyContext()总是返回一个新的上下文实例。

### 9.5 Spring Security的访问控制（授权）
在Spring Security中,负责访问控制决策的主要接口是AccessDecisionManager。 它具有一个decide方法，该方法拥有一个Authentication对象，“安全对象”（见下文）和适用于对象的安全元数据属性列表（例如访问所需的角色列表）。
#### 9.5.1 Security和AOP Advice
如果您熟悉AOP，您会发现有不同类型的通知可供选择：前置通知，后置通知，例外通知和环绕通知。环绕通知是非常有用的，因为advisor可以选择是否继续进行方法调用，是否修改响应，以及是否抛出异常。 Spring Security针对方法调用以及Web请求都提供了环绕通知。我们使用Spring的标准AOP支持来实现方法调用的各种增强，我们使用标准Filter来实现对Web请求的各种增强。（译者注：这段话翻译的很拗口，但大概意思就是Spring Security支持对方法的权限校验和对请求URL的权限校验，针对方法的权限校验采用AOP的实现方式，针对请求URL的权限校验采用的标准的过滤器实现方式）。

对于不熟悉AOP的人员，要了解的重点是Spring Security可以帮助您保护方法调用以及Web请求。大多数人都倾向于在其服务层上保护方法调用。这是因为在当前一代Java EE应用程序中，服务层是大多数业务逻辑驻留的地方。如果您只需要在服务层中保护方法调用，Spring的标准AOP就足够了。如果您需要直接保护安全域对象，您可能会发现AspectJ值得考虑。

您可以选择使用AspectJ或Spring AOP执行方法鉴权，也可以选择使用过滤器执行Web请求鉴权。您也可以一起使用这些几种方式的组合。主流使用模式是执行一些Web请求授权，再加上服务层上的一些Spring AOP方法调用授权。
#### 9.5.2 受保护对象和AbstractSecurityInterceptor
那么什么是“受保护对象”呢？ Spring Security使用该术语来引用作为安全性（例如授权决策）载体的任何对象。最常见的是方法调用和Web请求。

每个受支持的安全对象类型都有自己的拦截器类，这些拦截器类都是AbstractSecurityInterceptor的子类。重要的是，在调用AbstractSecurityInterceptor时，如果主体身份已经验证通过，则SecurityContextHolder将包含有效的Authentication。

AbstractSecurityInterceptor为处理安全对象请求提供了一致的工作流，通常为

1. 查找与本请求相关联的“配置属性”
2. 将安全对象，当前Authentication和配置属性提交给AccessDecisionManager进行授权决策
3. 可选地，更改发起调用的Authentication
4. 允许安全对象调用继续（假设访问被授予）
5. 一旦调用返回，继续调用AfterInvocationManager(如果配置了)。如果调用引发异常，则不会调用AfterInvocationManager。

##### 什么是配置属性？
“配置属性”可以被认为是对AbstractSecurityInterceptor类具有特殊含义的String。它们由框架内的接口ConfigAttribute表示。它们可能是简单的角色名称或具有更复杂的含义，这取决于AccessDecisionManager实现的复杂程度。AbstractSecurityInterceptor配置有一个SecurityMetadataSource，它用于查找安全对象的配置属性。通常这个配置将对用户来说是隐藏的。配置属性通常来源于安全方法上的注解或者受保护URL上的访问属性。例如，当我们在命名空间的介绍中看到类似<intercept-url pattern ='/secure/**' access ='ROLE_A，ROLE_B'/>的配置时，这就是匹配该模式的Web请求的配置属性是ROLE_A和ROLE_B。实际上，使用默认的AccessDecisionManager配置时，这表明只有当用户的GrantedAuthority属性与这两个配置属性相匹配时才允许用户访问。严格来说，它们只是属性，具体的访问决策取决于AccessDecisionManager的实现。使用前缀ROLE_是一个标记，用于指示这些属性是角色，应由Spring Security的RoleVoter使用。这仅在使用基于RoleVoter实现的AccessDecisionManager时才有用。我们将在授权章节中看到AccessDecisionManager的实现。
##### RunAsManager
假设AccessDecisionManager决定允许请求，那么AbstractSecurityInterceptor通常只会继续执行该请求。 话虽如此，在极少数情况下，用户可能希望使用由AccessDecisionManager调用RunAsManager处理的不同身份验证来替换SecurityContext内的Authentication。 这在相当不寻常的情况下可能是有用的，例如，如果Service层方法需要调用远程系统并呈现不同的身份。 因为Spring Security自动将安全身份从一个服务器传播到另一个服务器（假设您正在使用正确配置的RMI或HttpInvoker远程处理协议客户端），这可能很有用。（译者注：在某些情况下你可能会想替换保存在SecurityContext中的Authentication。这可以通过RunAsManager来实现的。在AbstractSecurityInterceptor的beforeInvocation()方法体中，在AccessDecisionManager鉴权成功后，将通过RunAsManager在现有Authentication基础上构建一个新的Authentication，如果新的Authentication不为空则将产生一个新的SecurityContext，并把新产生的Authentication存放在其中。这样在请求受保护资源时从SecurityContext中获取到的Authentication就是新产生的Authentication。待请求完成后会在finallyInvocation()中将原来的SecurityContext重新设置给SecurityContextHolder。AbstractSecurityInterceptor默认持有的是一个对RunAsManager进行空实现的NullRunAsManager。此外，Spring Security对RunAsManager有一个还有一个非空实现类RunAsManagerImpl，其在构造新的Authentication时是这样的逻辑：如果受保护对象对应的ConfigAttribute中拥有以“RUN_AS_”开头的配置属性，则在该属性前加上“ROLE_”，然后再把它作为一个GrantedAuthority赋给将要创建的Authentication（如ConfigAttribute中拥有一个“RUN_AS_ADMIN”的属性，则将构建一个“ROLE_RUN_AS_ADMIN”的GrantedAuthority），最后再利用原Authentication的principal、权限等信息构建一个新的Authentication进行返回；如果不存在任何以“RUN_AS_”开头的ConfigAttribute，则直接返回null。）
##### AfterInvocationManager
 在请求受保护的对象完成以后，可以通过afterInvocation()方法对返回值进行修改。AbstractSecurityInterceptor把对返回值进行修改的控制权交给其所持有的AfterInvocationManager了。AfterInvocationManager可以选择对返回值进行修改、不修改或抛出异常（如：后置权限鉴定不通过）。 由于高度可插拔，AbstractSecurityInterceptor会将控件传递给AfterInvocationManager，以便在需要时实际修改该对象。 这个类甚至可以完全替换对象，也可以抛出异常，或者不以任何方式更改它。 后调用检查只有在调用成功时才会执行。 如果发生异常，将跳过附加检查。

AbstractSecurityInterceptor及其相关对象如图9.1所示，Security interceptors 和"受保护对象"模型。

<center>图 9.1. Security interceptors 和"受保护对象"模型</center>
![](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/images/security-interception.png)

##### 扩展受保护对象模型
只有考虑采用全新方式拦截和授权请求的开发人员才需要直接操作受保护对象。 例如，可以构建一个新的受保护对象来保护对消息系统的调用。 任何需要被保护的资源都可以被列为受保护对象。 话虽如此，大多数Spring应用程序将简单地使用三个当前支持的受保护对象类型（AOP Alliance MethodInvocation，AspectJ JoinPoint和Web请求FilterInvocation）。
### 9.6 本地化
Spring Security支持异常消息的本地化。如果您的应用程序是为英语用户设计的，那么您无需执行任何操作，因此默认情况下所有安全消息均为英文。如果您需要支持其他语言环境，则本节会告诉你如何设置。

所有异常消息都可以进行本地化，包括与认证失败相关的消息和拒绝访问（授权失败）的异常消息。与开发人员或系统部署者的异常和日志记录消息（包括不正确的属性，违规接口违规，使用不正确的构造函数，启动时间验证，调试级日志记录）不会本地化，而是在Spring Security的代码中用英文硬编码。

在spring-security-core-xx.jar包中，您将找到一个org.springframework.security包，该包又包含一个messages.properties文件，以及一些常用语言的本地化版本。这应该由您的ApplicationContext引用，因为Spring Security类实现了Spring的MessageSourceAware接口，并期望消息解析器在应用程序上下文启动时注入。通常您需要做的是在应用程序上下文中注册一个bean来引用消息。一个例子如下所示：

```
<bean id="messageSource"
	class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
<property name="basename" value="classpath:org/springframework/security/messages"/>
</bean>
```
messages.properties根据标准资源Bundle命名，并表示Spring Security消息支持的默认语言。此默认文件为英文。

如果您希望自定义messages.properties文件或支持其他语言，则应该复制该文件，并相应地重命名，并将其注册到上述bean定义中。这个文件中没有大量的消息密钥，所以本地化不应该被认为是主要的。如果您确实执行此文件的本地化，请考虑通过记录JIRA任务并附加适当命名的本地化版本的messages.properties来与社区共享您的工作。

Spring Security依赖于Spring的本地化支持，以便查找相应的消息。为了使其工作，您必须确保请求的区域设置存储在Spring的org.springframework.context.i18n.LocaleContextHolder中。 Spring MVC的DispatcherServlet自动为您的应用程序执行此操作，但是由于Spring Security的过滤器在此之前被调用，因此LocaleContextHolder需要设置为在调用过滤器之前包含正确的区域设置。你可以自己做一个过滤器（它必须在web.xml中的Spring Security过滤器之前），或者你可以使用Spring的RequestContextFilter。有关使用Spring进行本地化的更多详细信息，请参阅Spring Framework文档。

“contacts”示例应用程序设置为使用本地化消息。
## 10 核心服务
现在我们对Spring Security架构及其核心类进行了高级的概述，接下来我们仔细研究一两个核心接口及其实现类，特别是AuthenticationManager，UserDetailsService和AccessDecisionManager。 这些类在该文档的其他部分还会经常出现，因此，首先要知道它们的配置及其操作方式。
### 10.1 AuthenticationManager, ProviderManager和AuthenticationProvider

AuthenticationManager只是一个接口，因此我们可以根据自己的业务逻辑自由来实现，但它在实践中是如何工作的呢？如果我们需要检查多个身份验证数据库或不同身份验证服务（如数据库和LDAP服务器）的组合，该怎么办？

在Spring Security中，AuthenticationManager的默认实现是ProviderManager，ProviderManager本身并不处理身份验证请求，它将身份认证委托给已配置的AuthenticationProvider的列表，在进行身份认证时会遍历AuthenticationProvider列表，以查看是否可以执行身份验证。每个AuthenticationProvider将抛出异常或返回完全填充的Authentication对象。还记得我们的好朋友，UserDetails和UserDetailsS​​ervice？如果没有，回到上一章，强化一下你的记忆。执行身份验证的最常见方法是加载相应的UserDetails，并检查用户输入的密码和加载的密码是否一致。DaoAuthenticationProvider就使用这种认证方法（见下文）。当构建完全填充的Authentication对象（从成功的认证返回并存储在SecurityContext中）时，将使用加载的UserDetails对象（特别是包含的GrantedAuthority）。

如果使用Spring Security命名空间配置，则Spring Security会在内部创建和维护ProviderManager实例，并通过使用命名空间认证提供程序元素（请参阅[命名空间章节](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#ns-auth-manager)）向其添加提供程序。在这种情况下，您不应该在应用程序上下文中声明一个ProviderManager bean。但是，如果您不使用命名空间，则可以这样声明：

```
<bean id="authenticationManager"
		class="org.springframework.security.authentication.ProviderManager">
	<constructor-arg>
		<list>
			<ref local="daoAuthenticationProvider"/>
			<ref local="anonymousAuthenticationProvider"/>
			<ref local="ldapAuthenticationProvider"/>
		</list>
	</constructor-arg>
</bean>
```

在上面的例子中，我们配置了三个认证提供者。它们按照配置的顺序以此进行身份认证（这通过使用列表来表示），每个提供者都可以尝试身份验证，或者通过简单地返回null来跳过身份验证。如果所有的认证提供者都返回null，那么ProviderManager将抛出一个ProviderNotFoundException异常。如果您有兴趣了解有关认证提供者链的更多信息，请参阅ProviderManager Javadoc。

例如，在基于Web表单登录的认证机制中，处理认证过程过滤器引用了ProviderManager实例，并通过ProviderManager实例处理其身份验证请求。身份认证提供者有时可以与身份验证机制互换，而在其他情况下，它将取决于特定的身份验证机制。例如，DaoAuthenticationProvider和LdapAuthenticationProvider与简单的任何基于用户名/密码的认证机制兼容，因此可以使用基于表单的登录或HTTP Basic身份验证。另一方面，一些认证机制创建一个认证请求对象，该对象只能由一种类型的AuthenticationProvider来解释。典型的例子是JA-SIG CAS，它使用服务票据的概念，因此只能由一个CasAuthenticationProvider进行身份验证。您不必太在意这一点，因为如果您忘记注册一个合适的认证提供者，则当尝试进行身份验证时，您将收到一个ProviderNotFoundException异常。

#### 10.1.1 认证成功时清除凭证

默认情况下（从Spring Security 3.1开始），ProviderManager将尝试从认证对象中清除成功认证请求返回的任何敏感凭证信息。这样可以防止密码被长期保留。

当您使用用户对象缓存时，可能会导致问题，例如无法改善无状态应用程序的性能。如果身份验证包含对缓存中对象的引用（例如UserDetails实例），并删除其凭据，则将无法再对缓存的值进行身份验证。如果您正在使用缓存，则需要考虑这一点。一个明显的解决方案是首先创建对象的副本，无论是在缓存实现中还是在创建返回的Authentication对象的AuthenticationProvider中。或者，您可以禁用ProviderManager上的eraseCredentialsAfterAuthentication属性。有关更多信息，请参阅Javadoc。
#### 10.1.2 DaoAuthenticationProvider

Spring Security提供的最简单的AuthenticationProvider实现是DaoAuthenticationProvider，它也是框架最早支持的。 它利用UserDetailsService（作为DAO）来查找用户名，密码和GrantedAuthority。 它只需通过将UsernamePasswordAuthenticationToken中提交的密码与UserDetailsService加载的密码进行比较即可对用户进行身份验证。 配置提供程序很简单：

```
<bean id="daoAuthenticationProvider"
	class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
<property name="userDetailsService" ref="inMemoryDaoImpl"/>
<property name="passwordEncoder" ref="passwordEncoder"/>
</bean>
```
PasswordEncoder是可选的。 PasswordEncoder提供从配置的UserDetailsService返回的UserDetails对象中显示的密码的编码和解码。 这将在[下面](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#core-services-password-encoding)更详细地讨论。

### 10.2 UserDetailsService实现

如本参考指南中前面提到的，大多数认证提供者都使用UserDetails和UserDetailsService接口。 回想一下，UserDetailsService接口的定义，该接口只有唯一的一个方法：

```
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```
该方法的返回值UserDetails是一个接口，它提供了验证用户名是否激活的方法以及对用户名，密码，授予用户的权限等属性的getter方法。 大多数认证提供者将使用UserDetailsService，即使用户名和密码实际上不被用作身份验证决策的一部分。 由于某些其他系统（如LDAP或X.509或CAS等）承担了实际身份认证的责任，这时loadUserByUsername返回的UserDetails对象对于该系统来说，只是为了使用其包含的GrantedAuthority信息。

UserDetailsService的实现是非常简单的，用户可以根据自己的持久性策略很容易地检索身份验证信息。 话虽如此，Spring Security确实为UserDetailsService提供了一些有用的基础实现，下面我们来看一下。
#### 10.2.1 In-Memory Authentication

创建一个自定义的UserDetailsService实现，从选择的持久性引擎中提取信息，这是很实用的，但是许多应用程序不需要这么复杂。 如果您正在构建原型应用程序或刚刚开始集成Spring Security，当您不想花时间配置数据库或编写UserDetailsService实现时，一个简单的选择是使用Security命名空间中的user-service元素：

```
<user-service id="userDetailsService">
<user name="jimi" password="jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
<user name="bob" password="bobspassword" authorities="ROLE_USER" />
</user-service>
```

这也可以使用外部属性文件配置：

```
<user-service id="userDetailsService" properties="users.properties"/>
```
属性文件中的配置格式如下：

```
username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]
```
例如如下的属性配置文件：

```
jimi=jimispassword,ROLE_USER,ROLE_ADMIN,enabled
bob=bobspassword,ROLE_USER,enabled
```

#### 10.2.2 JdbcDaoImpl
Spring Security还提供了从JDBC数据源获取认证信息的UserDetailsService实现。 在Spring Security内部使用的是Spring的JDBC数据源，因此，它避免了使用ORM框架来存储单一用户信息的复杂性。 如果您的应用程序使用ORM工具，您可能更愿意编写一个自定义UserDetailsService来重用已经创建的映射文件。 关于JdbcDaoImpl的示例配置如下所示：

```
<bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
<property name="driverClassName" value="org.hsqldb.jdbcDriver"/>
<property name="url" value="jdbc:hsqldb:hsql://localhost:9001"/>
<property name="username" value="sa"/>
<property name="password" value=""/>
</bean>

<bean id="userDetailsService"
	class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
<property name="dataSource" ref="dataSource"/>
</bean>
```
您可以通过修改上述DriverManagerDataSource来使用不同的关系数据库管理系统。 您也可以从JNDI获得的全局数据源，这与其他任何Spring配置一样。

##### 权限组

默认情况下，JdbcDaoImpl加载单个用户的权限，假设权限直接映射到用户（参见[数据库模式附录](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#appendix-schema)）。 另一种方法是将权限划分为组，并将组分配给用户。 有些人喜欢这种方式，是管理用户权限的一种手段。 有关如何启用权限组的更多信息，请参阅JdbcDaoImpl Javadoc。 组织架构也包含在附录中。
### 10.3 密码编码
Spring Security的PasswordEncoder接口用于以某种方式编码密码然后在存储到数据库中。密码不应该以明文形式存储。密码在存储时必须使用bcrypt等单向密码散列算法进行编码，bcrypt算法使用内置的不同的盐值来进行编码。密码编码时最好不要使用简单的哈希函数，如MD5或SHA，甚至是加盐版本的MD5和SHA。 Bcrypt故意设计为缓慢，并阻止离线密码破解，而标准散列算法快速，可以轻松地用用穷举算法进行破解。您可能认为这并不会影响你，因为您的密码数据库是安全的，脱机攻击并不是风险。如果你有这种想法，那么请进行一些研究，并阅读所有以这种方式受到妥协的高调网站，并为保护密码不安全而被劫持。使用org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder“是保护密码安全的一个不错的选择，它还有其他常用编程语言中的兼容实现，因此它也是跨平台密码加密的最佳选择。

如果您的系统是使用散列算法加密密码的遗留系统，那么您将需要使用与当前算法相匹配的编码器，至少直到您将用户迁移到更安全的方案（通常这将涉及要求用户设置一个新的密码，因为哈希是不可逆转的）。 Spring Security具有包含传统密码编码实现的包，即org.springframework.security.authentication.encoding。 DaoAuthenticationProvider可以注册新的或旧的PasswordEncoder类型。
#### 10.3.1 什么是hash
密码散列不是Spring Security所特有的，但对于不熟悉概念的用户来说，这是一个常见的混淆策略。 散列（或摘要）算法是一种单向函数，它从一些输入数据（如密码）产生一段固定长度的输出数据（散列）。 例如，字符串“password”（十六进制）的MD5哈希值是：

```
5f4dcc3b5aa765d61d8327deb882cf99
```
从某种意义上说，散列是“单向的”，即在给定散列值的情况下获得原始输入，或者甚至可能产生该散列值的任何可能的输入都是非常困难的（实际上是不可能的）。 这个特性使哈希值对于身份验证非常有用。 它们可以存储在您的用户数据库中，作为明文密码的替身，即使这些值受到威胁，也不会立即显示可用于登录的密码。 请注意，这也意味着您无法在编码密码后恢复密码。
#### 10.3.2 加盐后Hash
密码被哈希后的一个潜在问题是，如果使用通用单词作为原始密码输入，则相对容易破解哈希值。人们倾向于选择类似的密码，从以前被黑客攻击的网站上可以获得这些密码的巨大字典。例如，如果您使用谷歌搜索哈希值5f4dcc3b5aa765d61d8327deb882cf99，您将很快找到原始单词“password”。以类似的方式，攻击者可以从标准单词列表中构建散列词典，并使用它来查找原始密码。为了防止这种情况的发生，一种有效的方法是采用具有适当强度的密码策略，以防止使用常用单词时被暴力破解。另一个是在计算哈希时使用“盐”。这是在计算哈希之前与每个用户的一个额外的一串已知数据与密码相结合，然后在省城Hash值。理想情况下，数据应尽可能随机，但实际上任何盐值通常都比无盐值的安全性高。使用盐意味着攻击者必须为每个盐值构建一个单独的哈希字典，从而使攻击更加复杂（但这也不是不可能破解）。

Bcrypt在编码时自动为每个密码生成随机盐值，并以标准格式将其存储在bcrypt字符串中。
### 10.4 Jackson支持

Spring Security已经添加了Jackson支持，方便Spring Security持久化相关类使用。 在使用分布式Session（即session复制，Spring  Session等）时，序列化Spring Security相关类的性能会得到改善。

要使用Jackson，请将JacksonJacksonModules.getModules（ClassLoader）注册为Jackson模块。


# IV. Web应用安全
大多数用户在使用HTTP和Servlet API的应用程序中使用Spring Security框架。 在本部分中，我们将介绍Spring Security如何为应用程序的Web层提供身份验证和访问控制功能。 我们将会解释Spring Security命名空间的底层实现原理，并查看哪些类和接口用来实现Web层安全性。 在某些情况下，有必要使用传统的bean配置来完全控制配置，因此我们还将看到如何直接配置这些类而不使用命名空间。
## 13 Spring Security过滤器链
Spring Security在的Web层的基础设施完全基于标准的servlet过滤器来实现。Spring Security内部不使用servlet或任何其他基于servlet的框架（如Spring MVC），因此它没有对任何特定的Web技术产生较强的依赖。Spring Security在处理HttpServletRequest和HttpServletResponse时，并且不关心请求是来自浏览器，Web Service客户端，HttpInvoker还是AJAX应用程序。

Spring Security在内部维护一个过滤器链，其中每个过滤器都有特定的责任，根据需要哪些服务，从配置中添加或删除过滤器。过滤器的顺序很重要，因为它们之间有依赖关系。如果您已经使用命名空间配置，那么过滤器将自动为您配置，并且您不必明确定义任何Spring bean。如果您希望对Security过滤器链进行完全控制，或者您正在使用的功能在命名空间中不受支持，或者您正在使用自己的定制类，Spring Security支持自定义Bean配置。
### 13.1 DelegatingFilterProxy
当使用servlet过滤器时，您显然需要在web.xml中声明它们，否则它们将被servlet容器忽略。 在Spring Security中，过滤器类也是在应用程序上下文中定义的Spring bean，因此可以利用Spring丰富的依赖注入功能和生命周期接口。 Spring的DelegatingFilterProxy提供了web.xml和应用程序上下文之间的链接。

当使用DelegatingFilterProxy时，您将在web.xml文件中看到如下所示的内容：

```
<filter>
<filter-name>myFilter</filter-name>
<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
<filter-name>myFilter</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>
```
请注意，过滤器实际上是一个DelegatingFilterProxy，而不是实际实现过滤器逻辑的类。 DelegatingFilterProxy所做的是将Filter的方法委托给从Spring应用程序上下文获取的bean。 这使得Bean可以支持Spring Web应用程序上下文生命周期和灵活的配置。这些bean必须实现javax.servlet.Filter接口，它必须与filter-name元素中的名称相同。 有关详细信息，请阅读DelegatedFilterProxy的Javadoc。

### 13.2 FilterChainProxy
Spring Security的Web基础组件只能通过委派给FilterChainProxy的实例来使用。Security过滤器不应该独立使用。 理论上，您可以在应用程序上下文中声明所需的每个Spring Security过滤器bean，并为每个过滤器添加一个相应的DelegatingFilterProxy到web.xml，并且要确保每个过滤器的正确排序，但这样做是很麻烦的 如果你有很多过滤器，会使web.xml文件变得很凌乱。 FilterChainProxy允许我们在web.xml中只需添加一个配置项，并完全处理用于管理Web安全性bean的应用程序上下文文件。 它使用DelegatingFilterProxy进行连接，就像上面的示例一样，但是filter-name设置为bean的名称“filterChainProxy”。 然后在应用程序上下文中使用相同的bean名称声明过滤器链。 这里有一个例子：


```
<bean id="filterChainProxy" class="org.springframework.security.web.FilterChainProxy">
<constructor-arg>
	<list>
	<sec:filter-chain pattern="/restful/**" filters="
		securityContextPersistenceFilterWithASCFalse,
		basicAuthenticationFilter,
		exceptionTranslationFilter,
		filterSecurityInterceptor" />
	<sec:filter-chain pattern="/**" filters="
		securityContextPersistenceFilterWithASCTrue,
		formLoginFilter,
		exceptionTranslationFilter,
		filterSecurityInterceptor" />
	</list>
</constructor-arg>
</bean>
```
filter-chain命名空间元素用于方便设置应用程序中所需的安全过滤器链<sup>[6]</sup>。它将特定的URL模式映射到从filter元素指定的过滤器列表，并将它们组合到SecurityFilterChain类型的bean中。 pattern属性采用Ant路径，最特定的URI应该配置在最前面<sup>[7]</sup>。在运行时，FilterChainProxy将定位与当前Web请求相匹配的第一个URI模式，并且由filters属性指定的过滤器bean列表将应用于该请求。过滤器将按照定义的顺序进行调用，因此您可以完全控制应用于特定URL的过滤器链。

您可能已经注意到我们已经在过滤器链中声明了两个SecurityContextPersistenceFilter（ASC是allowSessionCreation的简称，SecurityContextPersistenceFilter的一个属性）。由于Web服务将不会在未来的请求中显示jsessionid，因此为这些用户代理创建HttpSession将 是浪费的。如果您有一个需要最大可扩展性的大容量应用程序，我们建议您使用上述方法。对于较小的应用程序，使用单个SecurityContextPersistenceFilter（其默认的allowSessionCreation为true）可能就足够了。

请注意，FilterChainProxy不会在配置的过滤器上调用标准过滤器生命周期方法。我们建议您使用Spring的应用程序上下文生命周期接口作为替代方法，就像任何其他Spring bean一样。

当我们查看如何使用命名空间配置设置Web安全性时，我们使用了一个名为“springSecurityFilterChain”的DelegatingFilterProxy。您现在应该可以看到这是由命名空间创建的FilterChainProxy的名称。

#### 13.2.1 绕过过滤器链

您可以使用属性filters =“none”作为过滤器bean列表的替代方法。 这将完全从安全过滤器链中省略请求模式。 请注意，与此路径匹配的任何内容将不会被应用任何身份验证或授权服务，并且可以随意访问。 如果要在请求期间利用SecurityContext的内容，则必须通过安全过滤器链。 否则SecurityContextHolder将不会被填充，内容将为null。
### 13.3过滤器顺序

过滤器在链中定义的顺序非常重要。无论您实际使用哪个过滤器，顺序应如下所示：

* ChannelProcessingFilter，因为它可能需要重定向到一个不同的协议
* SecurityContextPersistenceFilter，所以SecurityContext可以在Web请求开头的SecurityContextHolder中进行设置，当Web请求结束时，可以将SecurityContext的任何更改复制到HttpSession（准备用于下一个Web请求）
* ConcurrentSessionFilter，因为它使用SecurityContextHolder功能，需要更新SessionRegistry以反映主体的持续请求
* 身份验证处理机制 - UsernamePasswordAuthenticationFilter，CasAuthenticationFilter，BasicAuthenticationFilter等 - 以便SecurityContextHolder可以修改为包含有效的身份验证请求令牌
* SecurityContextHolderAwareRequestFilter，如果你正在使用它来安装一个Spring Security感知的HttpServletRequestWrapper到你的servlet容器
* JaasApiIntegrationFilter，如果JaasAuthenticationToken在SecurityContextHolder中，那么将将FilterChain作为JaasAuthenticationToken中的Subject处理
* RememberMeAuthenticationFilter，所以如果没有更早的认证处理机制更新了SecurityContextHolder，并且该请求提供了一个能够记住我的服务的cookie，那么一个合适的记住的Authentication对象将被放在那里
* AnonymousAuthenticationFilter，所以如果没有更早的认证处理机制更新了SecurityContextHolder，一个匿名认证对象将被放在那里
* ExceptionTranslationFilter，捕获任何Spring Security异常，以便可以返回HTTP错误响应或者可以启动适当的AuthenticationEntryPoint
* FilterSecurityInterceptor，用于在访问被拒绝时保护Web URI并引发异常


### 13.4 请求匹配和HttpFirewall
Spring Security有几个区域，您定义的模式针对传入的请求进行测试，以便决定如何处理该请求。当FilterChainProxy决定应该传递一个请求的过滤器链以及FilterSecurityInterceptor决定哪个安全约束适用于一个请求时，会发生这种情况。了解什么是机制，以及在使用定义的模式进行测试时使用的URL值很重要。

Servlet规范定义了可通过getter方法访问的HttpServletRequest的几个属性，以及我们可能需要匹配的属性。这些是contextPath，servletPath，pathInfo和queryString。 Spring Security仅对在应用程序中保护路径感兴趣，因此将忽略contextPath。不幸的是，servlet规范没有准确定义特定请求URI的servletPath和pathInfo的值将包含什么。例如，URL的每个路径段可以包含RFC 2396 [8]中定义的参数。规范不明确说明这些是否应包含在servletPath和pathInfo值中，并且行为在不同的servlet容器之间变化。存在将应用程序部署在不从这些值中剥离路径参数的容器中的危险时，攻击者可以将它们添加到请求的URL中，以使模式匹配成功或意外失败。 [9]。传入URL中的其他变体也是可以的。例如，它可以包含路径遍历序列（如/../）或多个正斜杠（//），这也可能导致模式匹配失败。在执行servlet映射之前，有些容器对这些进行规范化，但是其他容器则没有。为了防止这些问题，FilterChainProxy使用HttpFirewall策略来检查和包装请求。默认情况下，自动拒绝未归一化的请求，为了匹配目的，将删除路径参数和重复斜杠。 [10]。因此，必须使用FilterChainProxy来管理安全过滤器链。请注意，servletPath和pathInfo值由容器解码，因此您的应用程序不应具有包含分号的任何有效路径，因为这些部分将被删除以进行匹配。

如上所述，默认策略是使用Ant样式路径进行匹配，这可能是大多数用户的最佳选择。该策略是在AntPathRequestMatcher类中实现的，它使用Spring的AntPathMatcher来执行模式对连接的servletPath和pathInfo的不区分大小写的匹配，忽略了queryString。

如果由于某种原因，您需要一个更强大的匹配策略，您可以使用正则表达式。策略实现就是RegexRequestMatcher。有关更多信息，请参阅此类的Javadoc。

实际上，我们建议您在服务层使用方法安全性，以控制对应用程序的访问，并且不完全依赖于在Web应用程序级别定义的安全约束的使用。 URL更改，很难考虑应用程序可能支持的所有可能的URL以及请求如何被操纵。您应该尝试限制自己使用一些简单易懂的简单蚂蚁路径。始终尝试使用“deny-by-default”方法，其中最后定义了所有通配符（/或），并拒绝访问。

在服务层定义的安全性更强大，更难绕过，所以您应该始终利用Spring Security的方法安全性选项。

### 13.5 与其他基于过滤器的框架一起使用
如果您正在使用一些其他基于过滤器的框架，那么您需要确保Spring Security过滤器处于第一位。 这使SecurityContextHolder能够及时填写，以供其他过滤器使用。 示例是使用SiteMesh来装饰您的网页或Web框架，例如使用过滤器来处理其请求的Wicket。

### 13.6高级命名空间配置
正如我们前面在命名空间章节中看到的那样，可以使用多个http元素为不同的URL模式定义不同的安全配置。 每个元素在内部FilterChainProxy和应该映射到它的URL模式之间创建一个过滤器链。 元素将按照声明的顺序添加，因此必须首先声明最具体的模式。 这是另一个例子，对于类似于上述情况，应用程序支持无状态RESTful API以及用户使用表单登录的普通Web应用程序。

```
<!-- Stateless RESTful service using Basic authentication -->
<http pattern="/restful/**" create-session="stateless">
<intercept-url pattern='/**' access="hasRole('REMOTE')" />
<http-basic />
</http>

<!-- Empty filter chain for the login page -->
<http pattern="/login.htm*" security="none"/>

<!-- Additional filter chain for normal users, matching all other requests -->
<http>
<intercept-url pattern='/**' access="hasRole('USER')" />
<form-login login-page='/login.htm' default-target-url="/home.htm"/>
<logout />
</http>
```

[6]请注意，您需要将安全名称空间包含在应用程序上下文XML文件中才能使用此语法。 仍然支持使用过滤器链映射的较旧语法，但不建议使用构造函数注入。

[7]代替路径模式，request-matcher-ref属性可以用于指定一个RequestMatcher实例，用于更强大的匹配

[8]当浏览器不支持cookies并且在分号后面将jsessionid参数附加到URL时，您可能已经看到了这一点。 然而，RFC允许在URL的任何路径段中存在这些参数

[9]一旦请求离开FilterChainProxy，原始值将被返回，因此，应用程序仍然可用。

[10]因此，例如，原始请求路径/secure;hack=1/somefile.html;hack=2将作为/secure/somefile.html返回。

## 14 核心过滤器

有一些关键的过滤器将始终应用于基于Spring Security的Web应用程序中，因此我们首先查看这些过滤器类及其支持类和接口。 我们不会涵盖每个功能，如果你想了解每个类的详细信息，请查看对应的Javadoc。

### 14.1 FilterSecurityInterceptor

## 15. Spring Security与Servlet API集成
本节介绍Spring Security如何与Servlet API集成。 servletapi-xml示例应用程序演示了每种方法的用法。
### 15.1 Spring Security与Servlet 2.5+集成
#### 15.1.1 HttpServletRequest.getRemoteUser()

HttpServletRequest.getRemoteUser（）将返回当前用户名，即SecurityContextHolder.getContext().getAuthentication().getName()的结果。 如果要在应用程序中显示当前用户名，这可能很有用。 另外，还可以通过该方法检查用户名是否为空以此来判断用户是否已经验证通过。 判断用户是否被认证可用于确定是否应该在页面上显示某些UI元素（即，仅当用户被认证时才应该显示注销链接）。
#### 15.1.2 HttpServletRequest.getUserPrincipal()
HttpServletRequest.getUserPrincipal()将返回SecurityContextHolder.getContext().getAuthentication（）的结果。 这意味着它是一个身份验证，当使用用户名和密码进行身份验证时，该方法将返回UsernamePasswordAuthenticationToken的一个实例。 如果您需要有关用户的其他信息，这将非常有用。 例如，您可能已经创建了一个自定义的UserDetailsService，它返回一个包含用户姓氏和名字的自定义UserDetails。 您可以使用以下信息获取此信息：

```
Authentication auth = httpServletRequest.getUserPrincipal();
// assume integrated custom UserDetails called MyCustomUserDetails
// by default, typically instance of UserDetails
MyCustomUserDetails userDetails = (MyCustomUserDetails) auth.getPrincipal();
String firstName = userDetails.getFirstName();
String lastName = userDetails.getLastName();
```

> 应该注意的是，在整个应用程序中执行这么多的逻辑通常是不好的做法。 相反，应该集中它来减少Spring Security和Servlet API的任何耦合。

#### 15.1.3 HttpServletRequest.isUserInRole(String)

HttpServletRequest.isUserInRole（String）将确定SecurityContextHolder.getContext().getAuthentication().getAuthorities()是否包含GrantedAuthority，该角色传递到isUserInRole（String）。 通常，用户不能自动添加“ROLE_”前缀到此方法中。 例如，如果要确定当前用户是否具有“ROLE_ADMIN”权限，则可以使用以下命令：

```
boolean isAdmin = httpServletRequest.isUserInRole("ADMIN");
```
这可能有助于确定是否应该显示某些UI组件。 例如，只有当前用户是管理员时，才可能显示管理员链接。

### 15.2 Spring Security与Servlet 3+ 的集成
以下部分将介绍Spring Security与Servlet 3的集成。
#### 15.2.1 HttpServletRequest.authenticate(HttpServletRequest,HttpServletResponse)
可以使用HttpServletRequest.authenticate(HttpServletRequest，HttpServletResponse)方法来确保用户被认证。 如果未通过身份验证，则配置的AuthenticationEntryPoint将请求用户进行身份验证（即重定向到登录页面）。
#### 15.2.2 HttpServletRequest.login(String,String)
HttpServletRequest.login(String,String)方法用于使用当前的AuthenticationManager来验证用户。 例如，以下将尝试使用用户名“user”和密码“password”进行身份验证：

```
try {
httpServletRequest.login("user","password");
} catch(ServletException e) {
// fail to authenticate
}
```
> 如果您希望Spring Security处理身份验证失败的异常，则无需捕获ServletException。

#### 15.2.3 HttpServletRequest.logout()

HttpServletRequest.logout()方法可以用来退出当前用户。

通常这意味着SecurityContextHolder将被清除，HttpSession将无效，任何“记住我”的身份验证信息将被清除等。但是，配置的LogoutHandler实现将根据您的Spring Security配置而有所不同。 要注意，在HttpServletRequest.logout()被调用之后，你仍然负责写一个响应。 通常这将涉及重定向到欢迎页面。

#### 15.2.4 AsyncContext.start(Runnable)

[AsyncContext.start(Runnable)](http://docs.oracle.com/javaee/6/api/javax/servlet/AsyncContext.html)方法确保将您的认证凭据传播到新的线程。 当使用Spring Security的并发支持时，Spring Security会覆盖AsyncContext.start(Runnable)，以确保在处理Runnable时使用当前的SecurityContext。 例如，以下将输出当前用户的身份验证：

```
final AsyncContext async = httpServletRequest.startAsync();
async.start(new Runnable() {
	public void run() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		try {
			final HttpServletResponse asyncResponse = (HttpServletResponse) async.getResponse();
			asyncResponse.setStatus(HttpServletResponse.SC_OK);
			asyncResponse.getWriter().write(String.valueOf(authentication));
			async.complete();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
});
```
#### 15.2.5 Async Servlet支持

如果您使用的是基于Java的配置，那么您已经准备好了。 如果您正在使用XML配置，则需要进行一些更新。 第一步是确保您更新了web.xml以至少使用3.0模式，如下所示：

```
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
version="3.0">

</web-app>
```
接下来，您需要确保您的springSecurityFilterChain被设置为处理异步请求。

```
<filter>
<filter-name>springSecurityFilterChain</filter-name>
<filter-class>
	org.springframework.web.filter.DelegatingFilterProxy
</filter-class>
<async-supported>true</async-supported>
</filter>
<filter-mapping>
<filter-name>springSecurityFilterChain</filter-name>
<url-pattern>/*</url-pattern>
<dispatcher>REQUEST</dispatcher>
<dispatcher>ASYNC</dispatcher>
</filter-mapping>
```
配置完成！ 现在，Spring Security将确保您的SecurityContext也在异步请求上传播。

那么它如何工作呢？ 如果您没有真正的兴趣，请跳过本节的其余部分，否则请继续阅读。 大多数内置于Servlet规范中，但是Spring Security有一些调整可以确保正确使用异步请求。 在Spring Security 3.2之前，一旦提交了HttpServletResponse，SecurityContextHolder的SecurityContext就会自动保存。 这可能会导致异步环境中的问题。 例如，考虑以下几点：

```
httpServletRequest.startAsync();
new Thread("AsyncThread") {
	@Override
	public void run() {
		try {
			// Do work
			TimeUnit.SECONDS.sleep(1);

			// Write to and commit the httpServletResponse
			httpServletResponse.getOutputStream().flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}.start();
```

问题是Spring线程不知道这个Thread，所以SecurityContext不会传播给它。 这意味着当我们提交HttpServletResponse时，没有SecuriytContext。 当Spring Security自动将SecurityContext保存在提交HttpServletResponse上时，将丢失我们登录的用户。

自3.2版本以来，Spring Security非常聪明，因为一旦HttpServletRequest.startAsync（）被调用，就不再自动保存SecurityContext来提交HttpServletResponse。

### 15.3 Servlet 3.1+ Integration

以下部分将介绍Spring Security集成的Servlet 3.1方法。
#### 15.3.1 HttpServletRequest#changeSessionId()

HttpServletRequest.changeSessionId（）是在Servlet 3.1及更高版本中防止会话修复攻击的默认方法。

## 18.跨站请求伪造（CSRF）
本章研究 Spring Security对CSRF的支持
### 18.1 什么是CSRF
在研究Spring Security对CSRF支持之前，让我们先来了解一下CSRF的概念。我们将通过一个具体的例子来阐述CSRF的概念。
假如你的银行站点支持当前登录用户通表单的方式来进行转账。例如，HTTP请求如下：

```
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly
Content-Type: application/x-www-form-urlencoded

amount=100.00&routingNumber=1234&account=9876
```
现在假设你已经成功登陆你的银行网站，然后，在不退出的情况下访问一个恶意网站。 恶意网站包含一个HTML页面，其格式如下：

```
<form action="https://bank.example.com/transfer" method="post">
<input type="hidden"
	name="amount"
	value="100.00"/>
<input type="hidden"
	name="routingNumber"
	value="evilsRoutingNumber"/>
<input type="hidden"
	name="account"
	value="evilsAccountNumber"/>
<input type="submit"
	value="Win Money!"/>
</form>
```
你喜欢赢钱，所以你点击提交按钮。 在这个过程中，你无意中将100美元转移给了恶意用户。 之所以发生这种情况是因为，即使恶意网站无法访问您的cookies，但是与您的银行相关的cookies仍然与请求一起发送。

最糟糕的是，整个过程可能已经使用JavaScript自动完成。 这意味着你甚至不需要点击按钮。 那么我们如何保护自己免受这种攻击呢？
### 18.2 同步器令牌模式
上述之所以能够发起恶意攻击，是因为来自银行网站的HTTP请求和来自恶意网站的请求是完全一样的。这意味着服务器端无法拒绝来自恶意网站的请求，但允许来自银行网站的合法请求。为了防止CSRF攻击，我们需要确保恶意网站无法提供请求中的内容。

一种解决方案是使用同步器令牌模式。此解决方案是为了确保除了我们的会话cookie之外，每个请求还需要一个随机生成的令牌作为HTTP参数。提交请求时，服务器端必须查找参数的期望值，并将其与请求中的实际值进行比较。如果值不匹配，请求将失败。

我们可以放宽限制，只有在更新站点状态的每个HTTP请求中才要求加入令牌。这可以安全地完成，因为同源策略确保恶意站点无法读取响应。此外，我们不希望在HTTP GET中包含随机标记，因为这会导致令牌泄漏。

让我们来看看我们的例子将如何改变。假设随机生成的令牌存在于名为_csrf的HTTP参数中。例如，转账请求看起来像这样：

```
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly
Content-Type: application/x-www-form-urlencoded

amount=100.00&routingNumber=1234&account=9876&_csrf=<secure-random>
```

你会注意到我们添加了一个随机值的_csrf参数。 现在，恶意的网站将无法猜测_csrf参数（必须在恶意网站上明确提供）的正确值，并且当服务器端将实际令牌与预期令牌进行比较时，发现不一致，因此，转账的恶意攻击将失败。
### 18.3 何时启用CSRF攻击防御
什么时候应该使用CSRF保护？ 我们的建议是对于普通用户可以通过浏览器处理的任何请求使用CSRF保护。 如果您只创建非浏览器客户端使用的服务，则可能需要禁用CSRF保护。
#### 18.3.1 CSRF防御和JSON
一个常见的问题是“我需要对JavaScript所做的JSON请求进行CSRF防护吗？ 简而言之，这将视情况而定。 但是，您必须非常小心，因为存在会影响JSON请求的CSRF攻击。 例如，恶意用户可以使用以下格式创建带有CSRF攻击的JSON：

```
<form action="https://bank.example.com/transfer" method="post" enctype="text/plain">
<input name='{"amount":100,"routingNumber":"evilsRoutingNumber","account":"evilsAccountNumber", "ignore_me":"' value='test"}' type='hidden'>
<input type="submit"
	value="Win Money!"/>
</form>
```
这将产生以下JSON结构:

```
{ "amount": 100,
"routingNumber": "evilsRoutingNumber",
"account": "evilsAccountNumber",
"ignore_me": "=test"
}
```
如果一个应用程序没有对Content-Type类型进行校验，那么将利用这个漏洞进行CSRF攻击。 即使应用程序设置了对Content-Type进行了验证，那么在基于Spring MVC应用程序中仍然可以通过将URL后缀更新为以“.json”结尾进行攻击，如下所示：

```
<form action="https://bank.example.com/transfer.json" method="post" enctype="text/plain">
<input name='{"amount":100,"routingNumber":"evilsRoutingNumber","account":"evilsAccountNumber", "ignore_me":"' value='test"}' type='hidden'>
<input type="submit"
	value="Win Money!"/>
</form>
```

#### 18.3.2 CSRF和无状态浏览器应用程序
如果我的应用程序是无状态的呢？ 这并不一定意味着你受到保护。 事实上，如果用户不需要在Web浏览器中针对特定请求执行任何操作，则它们可能仍然容易受到CSRF攻击。

例如，考虑一个应用程序使用一个包含所有状态的自定义cookie（而不是JSESSIONID）来进行身份验证。 当CSRF攻击发生时，自定义cookie将与请求一起被发送，与我们前面的示例中发送的JSESSIONID cookie相同。

使用基本身份验证的用户也容易受到CSRF攻击，因为浏览器将自动在所有请求中包含用户名密码，这与前面示例中发送的JSESSIONID Cookie相同。
### 18.4 启用Spring Security CSRF防护
那么，使用Spring Security来保护我们的站点免受CSRF攻击需要采取哪些措施？ 下面概述了使用Spring Security的CSRF保护的步骤：

* 恰当的HTTP请求方法
* 配置CSRF保护
* 包含CSRF令牌

#### 18.4.1 恰当的HTTP请求方法
防止CSRF攻击的第一步是确保您的网站使用正确的HTTP动词。 具体来说，在配置Spring Security的CSRF之前，您需要确定您的应用程序使用PATCH，POST，PUT或DELETE来修改任何状态。

这不是Spring Security的限制，而是CSRF防御的一般要求。这是因为在HTTP GET请求中包含敏感信息会导致信息泄漏。 请参阅[RFC 2616规范的第15.1.3 对URI中的敏感信息进行编码](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3)的相关描述。
#### 18.4.2 配置CSRF保护
下一步是在您的应用程序中包含Spring Security的CSRF保护。 一些框架通过判断用户Session是否过期来判断CSRF令牌是否过期，但这会导致它自己的问题。 相反，默认情况下，Spring Security的CSRF保护将产生HTTP 403访问被拒绝。 这可以通过配置AccessDeniedHandler来以不同的方式处理InvalidCsrfTokenException异常。

从Spring Security 4.0开始，默认情况下使用XML配置启用CSRF保护。 如果您想禁用CSRF保护，则可以参考下面的XML配置。

```
<http>
	<!-- ... -->
	<csrf disabled="true"/>
</http>
```
默认情况下，使用Java配置启用CSRF保护。 如果您想禁用CSRF，则可以在下面看到相应的Java配置。 有关如何配置CSRF保护的其他选项，请参阅csrf()的Javadoc。

```
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	.csrf().disable();
}
}
```
#### 18.4.3 包含CSRF令牌

##### 表单提交
最后一步是确保在所有PATCH，POST，PUT和DELETE方法中包含CSRF标记。 一种方法是使用_csrf请求属性来获取当前的CsrfToken。 下面显示了使用JSP进行此操作的示例：

```
<c:url var="logoutUrl" value="/logout"/>
<form action="${logoutUrl}"
	method="post">
<input type="submit"
	value="Log out" />
<input type="hidden"
	name="${_csrf.parameterName}"
	value="${_csrf.token}"/>
</form>
```
更简单的方法是使用Spring Security JSP标记库中的csrfInput标记。

> 如果您正在使用Spring MVC <form：form>标记或Thymeleaf 2.1+,并且正在使用@EnableWebSecurity，则CsrfToken会自动包含在表单中（使用CsrfRequestDataValueProcessor）。

##### Ajax和JSON请求
如果您使用的是JSON，则无法在HTTP参数中提交CSRF令牌。 相反，您可以在HTTP请求头中提交Token令牌。 一个典型的用法是将CSRF令牌包含在meta标签中。 下面显示了在JSP中的例子：

```
<html>
<head>
	<meta name="_csrf" content="${_csrf.token}"/>
	<!-- default header name is X-CSRF-TOKEN -->
	<meta name="_csrf_header" content="${_csrf.headerName}"/>
	<!-- ... -->
</head>
<!-- ... -->
```
您可以使用Spring Security JSP标记库中较简单的csrfMetaTags标记，而不是手动创建元标记。
然后，您可以在所有的Ajax请求中包含令牌。 如果您使用的是jQuery，可以使用以下方法：

```
$(function () {
var token = $("meta[name='_csrf']").attr("content");
var header = $("meta[name='_csrf_header']").attr("content");
$(document).ajaxSend(function(e, xhr, options) {
	xhr.setRequestHeader(header, token);
});
});
```
作为jQuery的替代品，我们推荐使用cujoJS的rest.js. rest.js模块为以RESTful方式处理HTTP请求和响应提供了高级支持。 核心功能是通过将拦截器根据需要上下文化HTTP客户端,并且为HTTP客户端添加行为的能力。

```
var client = rest.chain(csrf, {
token: $("meta[name='_csrf']").attr("content"),
name: $("meta[name='_csrf_header']").attr("content")
});
```
配置的客户端可以与需要向CSRF保护资源发出请求的应用程序的任何组件共享。 rest.js和jQuery之间的一个重要区别是，只有使用配置的客户端发出的请求才会包含CSRF令牌，而对于所有请求都包含令牌的jQuery。 限定哪些请求接收令牌的能力有助于防止将CSRF令牌泄露给第三方。 有关rest.js的更多信息，请参阅rest.js参考文档。
##### CookieCsrfTokenRepository
可能会有用户想要将CsrfToken保存在cookie中。 默认情况下，CookieCsrfTokenRepository将写入名为XSRF-TOKEN的cookie，并从名为X-XSRF-TOKEN的头文件或HTTP参数_csrf中读取。 这些默认值来自[AngularJS](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)。

您可以使用以下方法在XML中配置CookieCsrfTokenRepository：

```
<http>
	<!-- ... -->
	<csrf token-repository-ref="tokenRepository"/>
</http>
<b:bean id="tokenRepository"
	class="org.springframework.security.web.csrf.CookieCsrfTokenRepository"
	p:cookieHttpOnly="false"/>
```

> 上面的配置显式设置cookieHttpOnly = false。 这是允许JavaScript（即AngularJS）读取它的必要条件。 如果您不需要直接使用JavaScript读取cookie，则建议省略cookieHttpOnly = false以提高安全性。

您可以使用以下命令在Java配置中配置CookieCsrfTokenRepository：

```
@EnableWebSecurity
public class WebSecurityConfig extends
		WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}
}
```

> 上面的配置显式设置cookieHttpOnly = false。 这是允许JavaScript（即AngularJS）读取它的必要条件。 如果您不需要直接使用JavaScript读取cookie，则建议省略cookieHttpOnly = false（而不是使用新的CookieCsrfTokenRepository()）来提高安全性。

### 18.5 CSRF警告
开启CSRF防护时会有一些注意事项。
#### 18.5.1 Token过期
Spring Security CSRF的第一个问题是，预期的CSRF令牌存储在HttpSession中，所以一旦HttpSession过期，你配置的AccessDeniedHandler将收到一个InvalidCsrfTokenException异常。 如果您使用默认的AccessDeniedHandler，浏览器将得到一个HTTP 403，并显示一个糟糕的错误消息。
> 有人可能会问，为什么预期的CsrfToken默认不存储在cookie中。 这是因为有漏洞，其中header（即指定cookie）可以由另一个域设置。 这与Ruby on Rails在 请求header为X-Requested-With存在时不再跳过CSRF检查的原因是一样的。 有关如何执行漏洞的详细信息，请参阅此webappsec.org线程。 另一个缺点是消除状态（即token过期），如果token受到威胁，则无法强制终止token。

解决当前用户遇到Token过期的简单方法是使用一些JavaScript，让用户知道他们的会话即将过期。 用户可以通过点击一个按钮来刷新会话。

另外，指定一个自定义的AccessDeniedHandler允许你以任何你喜欢的方式处理InvalidCsrfTokenException。 有关如何自定义AccessDeniedHandler的示例，请参阅本手册提供的[xml](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#nsa-access-denied-handler)和[Java配置](https://github.com/spring-projects/spring-security/blob/3.2.0.RC1/config/src/test/groovy/org/springframework/security/config/annotation/web/configurers/NamespaceHttpAccessDeniedHandlerTests.groovy#L64)的链接。

最后，可以将应用程序配置为使用不会过期的[CookieCsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#csrf-cookie)。 如前所述，这不如使用Session那样安全，但在很多情况下可以足够好。
#### 18.5.2 登陆
为了防止伪造登录请求，登录表单也应该防止CSRF攻击。由于CsrfToken存储在HttpSession中，这意味着只要CsrfToken令牌属性被访问，就会创建一个HttpSession。虽然这在RESTful/无状态架构中听起来很糟糕，但现实是状态对于实现实际安全性是必要的。没有状态，如果令牌受到威胁，我们无能为力。实际上，CSRF令牌规模相当小，对我们的架构的影响是微不足道的。

保护登录表单的常用技术是使用JavaScript函数在表单提交之前获取有效的CSRF令牌。通过这样做，不需要考虑Session超时（在前面的章节中讨论），因为Session是在表单提交之前创建的（假设CookieCsrfTokenRepository没有被配置），所以用户可以留在登录页面并在需要时提交用户名/密码。为了达到这个目的，你可以利用Spring Security提供的CsrfTokenArgumentResolver，并像这里描述的那样公开一个端点。
#### 18.5.3 退出
添加CSRF后，用后只能通过HTTP POST更新LogoutFilter。 这确保了在用户注销时需要CSRF令牌，并且恶意用户不能强行注销您的用户。

一种方法是使用表单注销。 如果你真的想要一个链接，你可以使用JavaScript来让链接执行一个POST（也许在一个隐藏的窗体上）。 对于禁用JavaScript的浏览器，您可以选择使用链接将用户引导至执行POST的注销确认页面。

如果你真的想使用HTTP GET注销，你可以这样做，但请记住这通常不建议。 例如，下面的Java配置将执行注销，使用任何HTTP方法请求URL/注销：

```
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}
}
```
#### 18.5.4 Multipart (文件上传)
使用multipart/form-data表单数据的CSRF保护有两种选择。 每个选择都有其折衷方案。

* [在Spring Security之前放置MultipartFilter](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#csrf-multipartfilter)
* [包含CSRF令牌](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/reference/htmlsingle/#csrf-include-csrf-token-in-action)

> 在将Spring Security的CSRF保护与multipart/form-data文件上传集成之前，请确保您的文件上传功能正确使用。 有关在Spring中使用multipart/form-data表单的更多信息可以在Spring参考的17.10 [Spring的multipart（文件上传）支持部分](https://docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/mvc.html#mvc-multipart)和[MultipartFilter](https://docs.spring.io/spring/docs/3.2.x/javadoc-api/org/springframework/web/multipart/support/MultipartFilter.html) javadoc中找到。

##### 在Spring Security之前放置MultipartFilter
第一个选择是确保在Spring Security过滤器之前指定MultipartFilter。 在Spring Security过滤器之前指定MultipartFilter意味着没有调用MultipartFilter的授权，这意味着任何人都可以在服务器上放置临时文件。 但是，只有授权用户才能提交由您的应用程序处理的文件。 一般来说，这是推荐的方法，因为临时文件上传应该对大多数服务器产生的影响可忽略。

为了确保在Java配置的Spring Security过滤器之前指定了MultipartFilter，用户可以覆盖beforeSpringSecurityFilterChain，如下所示：

```
public class SecurityApplicationInitializer extends AbstractSecurityWebApplicationInitializer {

	@Override
	protected void beforeSpringSecurityFilterChain(ServletContext servletContext) {
		insertFilters(servletContext, new MultipartFilter());
	}
}
```
为了确保在使用XML配置的Spring Security过滤器之前指定了MultipartFilter，用户可以确保MultipartFilter的<filter-mapping>元素位于web.xml中的springSecurityFilterChain之前，如下所示：

```
<filter>
	<filter-name>MultipartFilter</filter-name>
	<filter-class>org.springframework.web.multipart.support.MultipartFilter</filter-class>
</filter>
<filter>
	<filter-name>springSecurityFilterChain</filter-name>
	<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
	<filter-name>MultipartFilter</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
<filter-mapping>
	<filter-name>springSecurityFilterChain</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
```
##### 包含CSRF令牌
如果允许未经授权的用户上传临时文件是不可接受的，另一种方法是将MultipartFilter放置在Spring Security过滤器之后，并将CSRF作为查询参数包含在表单的action属性中。 下面显示了一个jsp的例子

```
<form action="./upload?${_csrf.parameterName}=${_csrf.token}" method="post" enctype="multipart/form-data">
```
这种方法的缺点是查询参数可能被泄露。 更为普遍的是，将敏感数据放在请求体或请求头中以确保其不泄漏是最好的做法。 附加信息可以在RFC 2616第15.1.3节中[对URI中的敏感信息进行编码](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3)。
#### 18.5.5 HiddenHttpMethodFilter
HiddenHttpMethodFilter应放置在Spring Security过滤器之前。 一般来说这是事实，但是在防止CSRF攻击时可能会产生额外的影响。

请注意，HiddenHttpMethodFilter只覆盖POST上的HTTP方法，所以这实际上不会导致任何实际问题。 不过，确保在Spring Security过滤器之前放置它仍然是最佳实践。
### 18.6 覆盖默认值
Spring Security的目标是提供保护您的用户免受攻击的默认设置。 这并不意味着你被迫接受所有的默认值。

例如，您可以提供一个自定义CsrfTokenRepository来覆盖CsrfToken的存储方式。

您也可以指定一个自定义的RequestMatcher来确定哪些请求受到CSRF的保护（也许您不在乎是否注销）。 简而言之，如果Spring Security的CSRF保护行为不像您想要的那样完美，您可以自定义行为。 有关如何使用XML和CsrfConfigurer javadoc进行这些自定义的详细信息，请参阅第41.1.18节“<csrf>”文档，以获取有关如何在使用Java配置时进行这些自定义的详细信息。
## 19. CORS
## 21. Session管理
在Spring Security中，与HTTP会话相关的功能由SessionManagementFilter和SessionAuthenticationStrategy接口联合来处理。 典型的用法包括Session固定攻击防御，Session超时检测和限定认证用户可同时打开多少个Session。
### 21.1 SessionManagementFilter
SessionManagementFilter根据SecurityContextHolder的当前内容检查SecurityContextRepository的内容，以确定用户是否在当前请求期间通过了身份验证，通常是通过非交互式身份验证机制（如预先身份验证或记住我[17]）。如果SecurityContextRepository包含安全上下文，则该过滤器不执行任何操作。如果SecurityContextRepository不包含安全上下文，并且线程本地变量SecurityContext包含（非匿名）Authentication对象，则过滤器将假定它们已被堆栈中的前面的过滤器认证，然后它将调用已配置的SessionAuthenticationStrategy。

如果当前用户未通过身份验证，则该过滤器将检查该请求的Session是否为有效的会话ID（例如，由于超时，可能导致Session过期），并将调用已经配置的InvalidSessionStrategy（如果已设置）。最常见的做法就是重定向到一个固定的URL，这被封装在标准实现SimpleRedirectInvalidSessionStrategy中。如前所述，在通过命名空间配置无效会话URL时也是重定向到一个固定的URL。
### 21.2 SessionAuthenticationStrategy
SessionAuthenticationStrategy被SessionManagementFilter和AbstractAuthenticationProcessingFilter使用，所以如果你正在使用一个自定义的form-login类，这时你需要将SessionAuthenticationStrategy实例注入到这两个过滤器类中。 在这种情况下，通过命名空间和自定义Bean的方式的典型配置可能如下所示：

```
<http>
<custom-filter position="FORM_LOGIN_FILTER" ref="myAuthFilter" />
<session-management session-authentication-strategy-ref="sas"/>
</http>

<beans:bean id="myAuthFilter" class=
"org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
	<beans:property name="sessionAuthenticationStrategy" ref="sas" />
	...
</beans:bean>

<beans:bean id="sas" class=
"org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy" />
```
注意，如果你的Session实现了HttpSessionBindingListener，并且你还将一个Bean（包括Spring会话范围的Bean）存在了此Session中，这时，如果你使用默认的SessionFixationProtectionStrategy可能会导致一些问题。 具体信息，请参阅此类的Javadoc文档以获取更多信息。
### 21.3 并发Session控制
Spring Security能够防止同一个账号主体同时对同一个应用程序进行多次身份验证。许多独立软件开发商利用这个来强制许可，而网络管理员喜欢这个功能，因为它有助于防止人们共享登录用户名。例如，您可以阻止用户“Batman”从两个不同的会话登录到Web应用程序。您可以使其以前的登录失效，也可以在尝试重新登录时报告错误，防止第二次登录。请注意，如果您采用第二种方式，那么未明确注销的用户（例如，刚刚关闭浏览器的用户）在其Session过期之前将无法再次登录。

Spring Security支持通过命名空间的方式进行并发Session控制的配置，因此请参考前面的Spring Security命名空间章节以获取最简单的配置，有时你需要自定义一些配置。

Spring Security针对并发Session控制，提供了SessionAuthenticationStrategy的专用实现类，该实现类名为ConcurrentSessionControlAuthenticationStrategy。

> 以前并发身份验证通过在ConcurrentSessionController控制器中注入ProviderManager，由ProviderManager来完成认证。它可以检测用户是否视图超过最大会话限制的允许数量。 但是，这种方法需要事先创建一个HTTP会话，这是不可取的。 在Spring Security 3中，用户首先由AuthenticationManager进行身份验证，一旦身份验证成功，将创建一个会话并检查是否允许打开另一个会话。

要使用并发会话支持，您需要将以下内容添加到web.xml中：

```
<listener>
	<listener-class>
	org.springframework.security.web.session.HttpSessionEventPublisher
	</listener-class>
</listener>
```
另外，你还需要将ConcurrentSessionFilter添加到您的FilterChainProxy中。 ConcurrentSessionFilter需要两个属性sessionRegistry（通常指向SessionRegistryImpl的实例）和expiredUrl（指向会话过期时显示的页面）。 通过命名空间方式来配置FilterChainProxy和其他默认bean的代码如下所示：

```
<http>
<custom-filter position="CONCURRENT_SESSION_FILTER" ref="concurrencyFilter" />
<custom-filter position="FORM_LOGIN_FILTER" ref="myAuthFilter" />

<session-management session-authentication-strategy-ref="sas"/>
</http>

<beans:bean id="concurrencyFilter"
class="org.springframework.security.web.session.ConcurrentSessionFilter">
<beans:property name="sessionRegistry" ref="sessionRegistry" />
<beans:property name="expiredUrl" value="/session-expired.htm" />
</beans:bean>

<beans:bean id="myAuthFilter" class=
"org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
<beans:property name="sessionAuthenticationStrategy" ref="sas" />
<beans:property name="authenticationManager" ref="authenticationManager" />
</beans:bean>

<beans:bean id="sas" class="org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy">
<beans:constructor-arg>
	<beans:list>
	<beans:bean class="org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy">
		<beans:constructor-arg ref="sessionRegistry"/>
		<beans:property name="maximumSessions" value="1" />
		<beans:property name="exceptionIfMaximumExceeded" value="true" />
	</beans:bean>
	<beans:bean class="org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy">
	</beans:bean>
	<beans:bean class="org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy">
		<beans:constructor-arg ref="sessionRegistry"/>
	</beans:bean>
	</beans:list>
</beans:constructor-arg>
</beans:bean>

<beans:bean id="sessionRegistry"
	class="org.springframework.security.core.session.SessionRegistryImpl" />
```

将监听器添加到web.xml中会导致每当HttpSession开始或终止时，都会将ApplicationEvent发布到Spring ApplicationContext。 这很重要，因为它允许在会话结束时通知SessionRegistryImpl。 没有它，即使用户退出其他会话或超时，用户将永远无法再次登录。

#### 21.3.1查询当前登陆用户及其会话的SessionRegistry
通过命名空间或者使用普通的bean的方式来配置并发Session控制还有一个好处，即为你提供一个可以在应用程序中直接使用的SessionRegistry的引用，所以即使你不想限制用户可拥有的会话数量，这样配置系统架构也是值得的。您可以将maximumSession属性设置为-1以允许无限制的会话。如果您使用的是命名空间的配置方式，则可以使用session-registry-alias属性为内部创建的SessionRegistry设置别名，并提供一个引用，您可以将其注入到您自己的bean中。

getAllPrincipals()方法为您提供当前已通过身份验证的用户列表。您可以通过调用getAllSessions(Object principal，boolean includeExpiredSessions)方法来列出用户的会话，该方法返回SessionInformation对象的列表。您也可以通过在SessionInformation实例上调用expireNow()来将此用户的Session设置为过期。当用户返回到应用程序时，将阻止他们继续进行。因此，您可能会发现这些方法在管理应用程序时很有用。请查阅Javadoc来获取更多信息。









