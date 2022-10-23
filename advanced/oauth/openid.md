# OpenID Connect

在本节中，我们将提供一些关于OpenID Connect的关键背景信息，这有助于理解我们将要讨论的一些漏洞。如果你是OAuth和OpenID Connect的新手，我们建议在尝试完成基于OpenID的实验之前先阅读这一部分。

## 什么是OpenID Connect？

OpenID Connect扩展了OAuth协议，提供了一个专门的身份和认证层，位于基本的OAuth实现之上。它增加了一些简单的功能，能够更好地支持OAuth认证用例。

OAuth在设计之初并没有考虑到认证；它的目的是在应用程序之间对特定的资源进行授权的一种手段。然而，许多网站开始定制OAuth作为一种认证机制使用。为了实现这一点，他们通常要求读取一些基本的用户数据，如果被授权此访问权限，则假设用户在OAuth提供商那边进行了自我认证。

这些普通的OAuth认证机制远非理想。首先，客户端应用无法知道用户何时何地如何对用户进行认证。由于这些实现都是一种自定义的变通方法，因此也没有标准的方法来请求用户数据。为了正确地支持OAuth，客户端应用程序将不得不为每个提供商配置单独的OAuth机制，每个提供商都有不同的端点，独特的作用域集等等。

OpenID Connect通过增加标准化的、与身份相关的功能，使通过OAuth进行的认证以一种更可靠和统一的方式进行，从而解决了很多问题。

## OpenID Connect是如何工作的？

OpenID Connect可以很好地融入正常的OAuth流中。从客户端应用的角度来看，主要的区别在于有一组额外的、标准化的作用域，对于所有的提供商都是如此，以及还有一个额外的响应类型：`id_token`。

### OpenID Connect 角色

OpenID Connect的角色与标准OAuth的角色基本相同。主要区别在于规范使用的术语略有不同。

- **依赖方** - 请求用户认证的应用。这与OAuth客户端应用是同义的。
- **最终用户** - 正在接受认证的用户。这与OAuth资源所有者同义。
- **OpenID提供商** - 配置为支持OpenID Connect的OAuth服务。

### OpenID Connect声明和作用域

术语“申明（claims）”是指在资源服务器上表示有关用户信息的`key:value`对。申明的一个例子可能是`"family_name":"Montoya"`。

与基本的OAuth不同，其作用域对每个提供商都是独一无二的，所有OpenID Connect服务都使用一套相同的作用域。为了使用OpenID Connect，客户端应用必须在授权请求中指定`openid`作用域。然后它们可以包括一个或多个其他标准的作用域：

- `profile`
- `email`
- `address`
- `phone`

这些作用域中的每一个都对应于OpenID规范中定义的用户声明子集的读取访问权限。例如，请求`openid profile`作用域将授权客户端应用对与用户身份有关的一系列声明的读取权限，如`family_name`、`given_name`、`birth_date`等。

### ID Token

OpenID Connect提供的另一个主要附加功能是`id_token`响应类型。这将返回一个使用JSON web signature（JWS）签名的JWT。JWT payload包含一个基于最初请求作用域的声明列表。它还包含用户上一次被OAuth服务认证的方式和时间信息。客户端应用可以利用这一点来决定用户是否得到了充分的认证。

使用`id_token`主要的好处是减少了客户端应用和OAuth服务之间需要发送的请求数量，这可以提供更好的整体性能。与其需要获得访问令牌，然后单独请求用户数据，不如在用户认证后立即将包含这些数据的ID token发送给客户端应用。

ID token中传输的数据的完整性是基于JWT加密签名，而不是像OAuth那样简单地依赖一个可信的通道。出于这个原因，使用ID token可能有助于防止一些中间人攻击。然而，鉴于用于签名验证的加密密钥是通过同一网络通道（通常暴露在`/.well-known/jwks.json`）传输的，一些攻击仍然是可能的。

请注意，OAuth支持多种响应类型，因此完全可以接受客户端应用同时发送的基本OAuth响应类型和OpenID Connect `id_token`响应类型的授权请求：

```
response_type=id_token token
response_type=id_token code
```

在这种情况下，ID token和code或访问令牌都将同时发送到客户端应用。

## 识别OpenID Connect

如果OpenID connect正在被客户端应用程序积极使用，这在授权请求中应该是显而易见的。最傻瓜式的检查方法是寻找强制性的`openid`作用域。

即使登录过程最初看起来没有使用OpenID Connect，也仍然值得检查OAuth服务是否支持它。可以简单地尝试添加`openid`作用域或将响应类型更改为`id_token`，并观察是否会导致错误。

与基本的OAuth一样，查看OAuth提供商的文档，看看是否有任何关于其OpenID Connect支持的有用信息，这也是一个好主意。还可以从`/.well-known/openid-configuration`标准端点访问配置文件。

## OpenID Connect漏洞

OpenID Connect的规范比基本的OAuth规范要严格得多，这意味着通常不太可能出现具有明显漏洞的古怪实现。也就是说，由于它只是位于OAuth之上的一层，因此客户端应用程序或OAuth服务仍然可能受到前面所看到的一些基于OAuth的攻击。事实上，你可能已经注意到，我们所有的OAuth认证实验也都是使用OpenID Connect的。

在本节中，我们将了解OpenID Connect一些额外的功能可能带来的一些额外漏洞。

### 不受保护的动态客户端注册

OpenID规范概述了一种允许客户端应用向OpenID提供商注册的标准化方式。如果支持动态客户端注册，客户端应用可以通过向一个专门的`/registration`端点发送`POST`请求来注册自己。此端点的名称通常在配置文件和文档中提供。

在请求正文中，客户端应用以JSON格式提交自己的关键信息。例如，它通常需要包含一组列入白名单的重定向URI。还可以提交一系列额外信息，如想要公开的端点的名称、应用程序的名称等等。一个典型的注册请求可能看起来像这样：

```http
POST /openid/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer ab12cd34ef56gh89

{
    "application_type": "web",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "client_name": "My Application",
    "logo_uri": "https://client-app.com/logo.png",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client-app.com/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    …
}
```

OpenID提供商应要求客户端应用对自身进行认证。在上面的例子中，使用的是一个HTTP Bearer token。但是，一些提供商会允许在没有任何认证的情况下进行动态客户端注册，这使得攻击者能够注册自己的恶意客户端应用。可能会产生各种后果，具体取决于如何使用这些攻击者可控属性的值。

例如，你可能已经注意到其中一些属性可以作为URI提供。如果其中任何一个被OpenID提供者访问，就可能导致二阶SSRF漏洞，除非采取额外的安全措施。

> **实验**：[通过OpenID动态客户端注册的SSRF](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration)

### 通过引用允许授权请求

到此为止，我们已经了解了提交授权请求所需参数的标准方法，即通过查询字符串。一些OpenID提供商可以选择将这些参数以JWT的方式传入。如果支持此功能，你可以发送一个指向JSON Web Token的`request_uri`参数，其中包含其余的OAuth参数及其值。而根据OAuth服务的配置，此`request_uri`参数是 SSRF的另一个潜在向量。

你还可以使用此功能来绕过这些参数值的验证。一些服务器可能会有效地验证授权请求中的查询字符串，但可能无法将相同的验证充分应用于JWT中的参数，包括`redirect_uri`。

要检查此选项是否被支持，应该在配置文件和文档中查找`request_uri_parameter_supported`选项。或者，可以直接尝试添加`request_uri`参数，看看它是否有效。你会发现有些服务器支持这一功能，即使它们在文档中没有明确提到它。
