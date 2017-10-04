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
现在我们对Spring Security架构及其核心类进行了高级的概述，我们来仔细研究一两个核心接口及其实现，特别是AuthenticationManager，UserDetailsService和AccessDecisionManager。 这些类在该文档的其他部分还会经常出现，因此，首先要知道它们的配置及其操作方式。
10.1 AuthenticationManager, ProviderManager和AuthenticationProvider
