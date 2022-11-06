# JWT攻击

在本节中，我们将了解JSON web tokens （JWT）的设计问题和有缺陷的处理是如何使网站易受到各种高危攻击的。由于JWT最常用于认证、会话管理和访问控制机制，因此这些漏洞可能会危及整个网站及其用户。

如果不熟悉JWT及其工作原理，也不用担心。我们将在后面介绍所有相关细节。并且还提供了一些故意易受攻击的实验，以便你可以针对实际目标安全地利用这些漏洞进行练习。

![](https://portswigger.net/web-security/jwt/images/jwt-infographic.jpg)

>**实验**
>
>如果你已经熟悉了JWT攻击背后的基本概念，只想在一些现实的、故意易受攻击的目标上练习利用它们，可以从下面的链接中访问本主题中的所有实验。
>
>[查看所有JWT实验](https://portswigger.net/web-security/all-labs#jwt)

>**Tip**
>
>从[Burp Suite Professional 2022.5.1](https://portswigger.net/burp/releases/professional-community-2022-5-1?requestededition=professional)开始，[Burp Scanner](https://portswigger.net/burp/vulnerability-scanner)可以代表你自动检测JWT机制中的一些漏洞。欲了解更多信息，请参阅**Target > Issued definitions**选项上的相关问题定义。

## 什么是JWT？

JSON web tokens（JWT）是一种标准化格式，用于在系统之间发送经过加密签名的JSON数据。它们理论上可以包含任何类型的数据，但最常用于发送关于用户的（“声明”）信息，作为认证、会话处理和访问控制机制的一部分。

与传统的会话令牌不同，服务器所需的所有数据都存储在JWT本身的客户端中。这使得JWT成为高度分布式网站的流行选择，在这些网站中，用户需要与多个后端服务器进行无缝交互。

### JWT格式

JWT由3部分组成：标头（header）、有效负载（payload）和签名（signature）。它们都由一个点分隔，如下所示：

```jwt
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

JWT的标头和有效负载部分只是base64url编码的JSON对象。标头包含有关令牌本身的元数据，而有效负载包含有关用户的实际“声明”（claims）。例如，你可以对上述令牌中的有效负载进行解码，将显示如下声明。

```json
{
    "iss": "portswigger",
    "exp": 1648037164,
    "name": "Carlos Montoya",
    "sub": "carlos",
    "role": "blog_author",
    "email": "carlos@carlos-montoya.net",
    "iat": 1516239022
}
```

在大多数情况下，有权访问令牌的任何人都可以轻松读取或修改此数据。因此，任何基于JWT机制的安全性都严重依赖于加密签名。

### JWT签名

颁发令牌的服务器通常通过对标头和有效负载进行哈希处理来生成签名。在某些情况下，它们还会对产生的哈希值进行加密。无论哪种方式，这个过程都涉及到一个签名密钥。这种机制为服务器提供了一种方法，以验证令牌中的任何数据自颁发以来都没有被篡改过：

- 由于签名直接源自令牌的其余部分，因此更改标头或有效负载的一个字节都会导致签名不匹配。
- 在不知道服务器签名密钥的情况下，不可能为给定的标头或有效负载生成正确的签名。

> **Tip**
>
> 如果你想更好地了解JWT的构建方式，可以使用`jwt.io`上的调试器来试验任意令牌。

### JWT vs JWS vs JWE

JWT规范实际上是非常有限的。它只定义了一种代表（“声明”）信息的格式，作为一个可以在双方之间传输的JSON对象。在实践中，JWT并没有真正作为一个独立的实体来使用。JWT规范由JSON Web Signature（JWS）和JSON Web Encryption（JWE）规范扩展，它们定义了实际实现JWT的具体方法。

![](https://portswigger.net/web-security/jwt/images/jwt-jws-jwe.jpg)

换句话说，JWT通常是一个JWS或JWE令牌。当人们使用术语“JWT”时，几乎都是指JWS令牌。JWE非常相似，只是令牌的实际内容是加密的，而不仅仅是编码的。

> **注意**
>
> 为简单起见，在这些材料中，“JWT”主要指的是JWS令牌，尽管所描述的一些漏洞也可能适用于JWE令牌。

## 什么是JWT攻击？

JWT攻击涉及用户向服务器发送修改过的JWT，以达到恶意的目的。通常情况下，这个目的是通过冒充已经通过认证的用户，绕过认证和访问控制。

## JWT攻击有什么影响？

JWT攻击的影响通常很严重。如果攻击者能够用任意值创建自己的有效令牌，他们可能会提升自己的权限或者冒充其他用户，完全控制其他用户的账户。

## JWT攻击的漏洞是如何产生的？

JWT漏洞的产生通常是由于应用程序本身对JWT的处理存在缺陷。与JWT有关的各种规范在设计上相对灵活，允许网站开发人员自行决定许多实现细节。即使是在使用久经考验的库，也可能导致他们意外地引入漏洞。

这些实现缺陷通常意味着JWT的签名没有被正确验证。使得攻击者可以通过令牌的有效负载篡改传递给应用程序的值。即使签名得到了可靠的验证，它是否真的可以被信任在很大程度上取决于服务器的密钥是否保持私密。如果这个密钥以某种方式被泄露，或者可以被猜解或暴力破解，那么攻击者就可以为任意令牌生成一个有效的签名，从而破坏整个机制。

## 如何在Burp Suite中使用JWT

如果你过去没有使用过JWT，我们建议你在尝试本主题的实验之前先熟悉Burp Suite的相关功能。

> **阅读更多**
>
> [在Burp Suite中使用JWT](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite)

## 利用有缺陷的JWT签名验证

根据设计，服务器通常不存储有关它们发出的JWT的任何信息。相反，每个令牌是一个完全独立的实体。这样会有几个优点，但也引入了一个基本问题——服务器实际上并不知道令牌的原始内容，甚至不知道原始签名是什么。因此，如果服务器没有正确地验证签名，就没有什么可以阻止攻击者对令牌的其余部分进行任意更改。

例如，考虑一个包含以下声明的JWT：

```json
{
    "username": "carlos",
    "isAdmin": false
}
```

如果服务器根据这个`username`来识别会话，那么修改其值可能使攻击者能够冒充其他登录用户。同样，如果`isAdmin`值被用于访问控制，这可能为权限提升提供了一个简单的载体。

在前几个实验中，你会看到一些例子，说明这些漏洞在真实世界的应用中可能会出现。

### 接受任意签名

JWT库通常提供一种验证令牌的方法和另一种仅对其进行解码的方法。例如，Node.js `jsonwebtoken`库具有`verify()`和`decode()`两种方法。

有时，开发者会混淆这两种方法，只将传入的令牌传递给`decode()`方法。实际上这意味着应用程序根本不验证签名。

> **实验**
>
> [通过未经验证的签名绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

### 接受没有签名的令牌

在其他方面，JWT标头包含一个`alg`参数。这用来告诉服务器使用哪种算法来对令牌进行签名，因此在验证签名时需要使用哪种算法。

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

这在本质上是有缺陷的，因为服务器没有选择，只能隐含地信任来自令牌的用户可控输入，此时令牌根本没有被验证过。换句话说，攻击者可以直接影响服务器如何检查令牌是否值得信任。

JWT可以使用一系列不同的算法进行签名，但也可以不签名。在这种情况下，`alg`参数被设置为`none`，表示所谓的“不安全的JWT”。由于这种情况有明显的危险性，服务器通常会拒绝没有签名的令牌。然而，由于这种过滤依赖于字符串解析，有时可以使用经典的混淆技术绕过这些过滤器，例如混合大写和意外编码。

> **注意**
>
> 即使令牌未签名，有效负载部分仍必须以尾随点来结束。

> **实验**
>
> [通过有缺陷的签名验证绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)

## 暴力破解密钥

一些签名算法，如HS256（HMAC + SHA-256），使用一个任意的、独立的字符串作为密钥。就像密码一样，这个密钥不能被攻击者轻易猜到或暴力破解，这一点至关重要。否则，他们可能会用他们喜欢的任何标头和有效负载值创建JWT，然后使用密钥以有效的签名重新签名令牌。

在实现JWT应用时，开发人员有时会犯一些错误，比如忘记更改默认或占位符密码。他们甚至可能复制和粘贴在网上找到的代码片段，然后忘记更改作为示例提供的硬编码密码。在这种情况下，攻击者使用[众所周知的密钥字典](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)来暴力破解服务器的密码是很容易的。

### 使用hashcat暴力破解密钥

我们推荐使用hashcat来暴力破解密钥。你可以[手动安装hashcat](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_install_hashcat)，但它也预装在Kali Linux上，随时可以使用。

> **笔记**
>
> 如果你使用的是Kali的预构建VirtualBox镜像，而不是裸机安装版本，可能会没有足够的内存分配来运行hashcat。

你只需要一个来自目标服务器的有效的、有签名的JWT和一个[众所周知的密钥字典](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)。然后你可以运行以下命令，将JWT和字典作为参数传递：

```bash
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Hashcat使用字典中的每个密钥对JWT的标头和有效负载进行签名，然后将得到的签名与服务器的原始签名进行比较。如果任何一个签名匹配，hashcat就会以下列格式输出已识别的密钥，以及其他各种细节：

```
<jwt>:<identified-secret>
```

> **注意**
>
> 如果你运行该命令不止一次，则需要加入`--show`参数来输出结果。

由于hashcat在你的机器上本地运行，不依赖于向服务器发送请求，这个过程非常快，即使是在使用一个巨大的字典时也是如此。

一旦确定了密钥，就可以用它为任何你喜欢的JWT标头和有效负载生成一个有效的签名。关于如何在Burp Suite中重新签名一个修改过的JWT的细节，请看[签名JWT]()。

> **实验**
>
> [通过弱签名密钥绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)

如果服务器使用非常弱的密钥，甚至可以逐个字符地进行暴力破解，而不是使用字典。

## JWT标头参数注入

根据JWS规范，只有`alg`标头参数是强制性的。然而在实践中，JWT标头（也被称为JOSE标头）通常包含几个其他参数。以下是攻击者特别感兴趣的。

- `jwk`（JSON Web Key） —— 提供一个表示密钥的嵌入式 JSON 对象。
- `jku`（JSON Web Key Set URL） —— 提供一个URL，服务器可以从中获取包含正确密钥的密钥集。
- `kid`（Key ID） —— 提供一个 ID，在有多个密钥可供选择的情况下，服务器可以使用该ID来识别正确的密钥。根据密钥的格式，这可能有一个匹配的`kid`参数。

如你所见，这些用户可控的参数每个都告诉接收服务器在验证签名时要使用哪个密钥。在本节中，你将学习如何利用这些来注入使用你自己的任意密钥而不是服务器的密钥签名修改过的JWT。

### 通过jwk参数注入自签名JWT

JSON Web Signature（JWS）规范描述了一个可选的`jwk`标头参数，服务器可以使用该参数将其公钥直接嵌入JWK格式的令牌本身中。

> **JWK**
>
> JWK（JSON Web Key）是一种以JSON对象表示密钥的标准化格式。

你可以在以下JWT标头中看到一个示例：

```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

> 公钥和私钥
>
> 如果你不熟悉“公钥”和“私钥”这两个术语，我们已经将其作为算法混淆攻击材料的一部分进行了介绍。有关详细信息，请参阅[对称与非对称算法](https://portswigger.net/web-security/jwt/algorithm-confusion#symmetric-vs-asymmetric-algorithms)。

理想情况下，服务器应该只使用有限的公钥白名单来验证JWT签名。但是，配置不当的服务器有时会使用`jwk`参数中嵌入的任何密钥。

你可以利用这种行为，用自己的RSA私钥签署一个修改过的JWT，然后将匹配的公钥嵌入`jwk`标头中。

虽然可以在Burp中手动添加或修改`jwk`参数，但[JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)扩展提供了一个有用的功能，帮助你测试此漏洞：

1. 加载扩展后，在Burp的主选项卡栏中，转到**JWT Editor Keys**选项卡。
2. 生成新的RSA密钥。
3. 发送包含JWT的请求到Burp Repeater。
4. 在消息编辑器中，切换到扩展生成的**JSON Web Token**选项卡，然后根据需要修改令牌的有效负载。
5. 点击**Attack**，然后选择**Embedded JWK**。出现提示时，选择你新生成的RSA密钥。
6. 发送请求，测试服务器的响应情况。

也可以通过自己添加`jwk`标头来手动执行此攻击。然而，你可能还需要更新JWT的`kid`标头参数，以匹配嵌入密钥的`kid`。扩展程序的内置攻击为你解决了这个步骤。

> **实验**
>
> [通过jwk标头注入绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)

### 通过jku参数注入自签名JWT

某些服务器不直接使用`jwk`标头参数来嵌入公钥，而是让你使用`jku`（JWK Set URL）标头参数来引用一个包含密钥的JWK Set。当验证签名时，服务器会从该URL获取相关密钥。

> **JWK Set**
>
> 一个JWK Set是一个JSON对象，其中包含代表不同键的JWK数组。你可以在下面看到一个示例。

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

像这样的JWK Set有时会通过一个标准端点公开暴露，如`/.well-known/jwks.json`。

比较安全的网站只会从受信任的域中获取密钥，但有时可以利用URL解析的差异来绕过这种过滤。我们在关于SSRF的专题中介绍了一些这方面的例子。

> **实验**
>
> [通过jku标头注入绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)

### 通过kid参数注入自签名JWT

服务器可能会使用多个加密密钥来签名不同类型的数据，而不仅仅只是JWT。出于这个原因，JWT的标头部分可能包含一个`kid`（Key ID）参数，该参数帮助服务器在验证签名时确定使用哪个密钥。

验证密钥通常被存储为JWK Set。在这种情况下，服务器可以简单地查找与`kid`令牌相同的JWK。然而，JWS规范并没有为此ID定义具体的结构，它只是开发者选择的一个任意字符串。例如，他们可能使用`kid`参数来指向数据库中的一个特定条目，甚至是一个文件的名称。

如果这个参数也易受到目录遍历的影响，攻击者就有可能迫使服务器使用其文件系统中的任意文件作为验证密钥。

```json
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

如果服务器还支持使用对称算法签名的JWT，这就尤其危险。在这种情况下，攻击者可能会将`kid`参数指向一个可预测的静态文件，然后用一个与该文件内容相匹配的密钥对JWT进行签名。

从理论上讲，你可以对任何文件执行此操作，但最简单的方法之一是利用`/dev/null`，它存在于大多数Linux系统上。由于这是一个空文件，获取它会返回null。因此，使用一个Base64编码的空字节对令牌进行签名将产生一个有效的签名。

> **实验**
>
> [通过kid标头路径遍历绕过JWT认证](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)

如果服务器将其验证密钥存储在数据库中，则`kid`标头参数也是一个潜在的[SQL注入](https://portswigger.net/web-security/sql-injection)攻击的载体。

### 其他有趣的JWT标头参数

以下标头参数也可能是攻击者感兴趣的：

- `cty`（Content Type）—— 有时用于声明JWT有效负载中内容的媒体类型。这通常从标头中省略，但底层解析库可能还是支持它。如果你已经找到了绕过签名验证的方法，可以尝试注入`cty`标头以将内容类型更改为`text/xml`或`application/x-java-serialized-object`，这可能会为XXE和反序列化攻击提供新的载体。
- `x5c`（X.509证书链） —— 有时用于传递对JWT进行数字签名的X.509公钥证书或证书链。此标头参数可用于注入自签名证书，类似于上面讨论的`jwk`标头注入攻击。由于X.509格式及其扩展的复杂性，解析这些证书也可能引入漏洞。这些攻击的细节超出了本材料的范围，但要了解更多细节，请查看[CVE-2017-2800](https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293)和[CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633)。

## JWT算法混淆

即使服务器使用了无法暴力破解的强密钥，你仍然可以通过使用开发人员未预料到的算法签名令牌来伪造有效的JWT。这被称为算法混淆攻击。

> **阅读更多**
>
> [JWT算法混淆攻击](./algorithm-confusion.md)

## 如何防范JWT攻击

你可以通过采取以下高级措施来保护自己的网站免受所涉及的许多攻击：

- 使用最新的库来处理JWT，并确保开发人员完全了解它的工作原理以及任何安全隐患。新式的库使你很难在无意中不安全地实现它们，但由于相关规范具有固有的灵活性，这并不是万无一失。
- 确保对收到的任何JWT都进行可靠的签名验证，并考虑边缘案例，如使用意外算法签名的JWT。
- 对`jku`标头实施严格的主机允许白名单。
- 确保不会受到通过`kid`标头参数进行的路径遍历或SQL注入的影响。

### JWT处理的其他最佳实践

尽管对于避免引入漏洞来说并非绝对必要，但我们还是建议在你的应用程序中使用JWT时遵循以下最佳实践：

- 始终为你发出的任何令牌设置过期日期。
- 尽可能避免在URL参数中发送令牌。
- 包括`aud`（受众）声明（或类似），以指定令牌的预接收者。这可以防止它被用在不同的网站上。
- 使颁发服务器能够撤销令牌（例如在注销时）。

