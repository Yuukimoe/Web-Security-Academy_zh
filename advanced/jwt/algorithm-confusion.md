# 算法混淆攻击

算法混淆攻击（也称为密钥混淆攻击）发生在当攻击者能够迫使服务器使用不同于网站开发者预期的算法来验证JWT的签名时。如果这种情况没有得到妥善处理，可能会使攻击者能够伪造包含任意值的有效JWT，而无需知道服务器的签名密钥。

## 对称与非对称算法

JWT可以使用一系列不同的算法进行签名。其中一些，如HS256（HMAC + SHA-256）使用“对称”密钥。这意味着服务器使用一个单个的密钥来签名和验证令牌。显然这需要保密，就像密码一样。

![](https://portswigger.net/web-security/jwt/images/jwt-symmetric-signing-algorithm.jpg)

其他算法，如RS256（RSA + SHA-256）使用“非对称”密钥对。包含一个私钥，服务器用它来签名令牌，和一个数学上相关的公钥，可用于验证签名。

![](https://portswigger.net/web-security/jwt/images/jwt-asymmetric-signing-algorithm.jpg)

顾名思义，私钥必须保密，但公钥通常是共享的，以便任何人都可以验证服务器颁发的令牌签名。

## 算法混淆漏洞是如何产生的？

算法混淆漏洞通常是由于JWT库的实现存在缺陷而产生的。尽管实际的验证过程因使用的算法而不同，但许多库提供了一个单一的、与算法无关的方法来验证签名。这些方法依赖于令牌标头中的`alg`参数来确定它们应该执行的验证类型。

下面的伪码显示了一个简化的示例，以说明在JWT库中这个泛型`verify()`方法的声明可能是什么样子：

```javascript
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```

当随后使用该方法的网站开发者认为它将专门处理使用RS256等非对称算法签名的JWT时，问题就出现了。由于这个有缺陷的假设，他们可能总是将一个固定的公钥传递给该方法，如下所示：

```javascript
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```

在这种情况下，如果服务器收到一个使用HS256这样的对称算法签名的令牌，则库的泛型`verify()`方法会将公钥视为HMAC密钥。这意味着攻击者可以使用HS256和公钥来对令牌进行签名，服务器将使用相同的公钥来验证该签名。

> **注意**
>
> 用于签名令牌的公钥必须与存储在服务器上的公钥绝对一致。这包括使用相同的格式（如X.509 PEM）以及保留任何非打印字符，如换行符。在实践中，可能需要尝试不同的格式才能使这种攻击奏效。

## 执行算法混淆攻击

算法混淆攻击通常涉及以下高级步骤：

1. 获取服务器的公钥
2. 将公钥转换为合适的格式
3. 创建一个恶意的JWT，修改有效负载并将`alg`标头设置为HS256
4. 使用HS256对令牌进行签名，将公钥作为密钥

在本节中，我们将更详细地介绍此过程，演示如何使用Burp Suite执行此类攻击。

### 第 1 步 - 获取服务器的公钥

服务器有时会通过映射到`/jwks.json`或`/.known/jwks.json`的标准端点，将其公钥作为JSON Web Token（JWK）对象公开。这些可存储在一个名为`keys`的JWK数组中，称其为JWK Set。

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

即使密钥没有公开暴露，也可以从一对现有的JWT中提取它。

### 第 2 步 - 将公钥转换为合适的格式

---

尽管服务器可能会以JWK格式公开其公钥，但在验证令牌的签名时，它将使用其本地文件系统或数据库中自己的密钥副本。这可能是以不同的格式存储的。

为了使攻击奏效，用于签名JWT的密钥版本必须与服务器本地副本相同。除了格式相同之外，每个字节都必须相匹配，包括任何非打印字符。

出于本示例的目的，假设我们需要X.509 PEM格式的密钥。你可以使用Burp中的JWT Editor扩展将JWK转换为PEM，方法如下：

1. 加载扩展后，在Burp的主选项卡栏中，转到**JWT Editor Keys**选项卡。
2. 单击**New RSA**密钥。在对话框中，粘贴你之前获得的JWK。
3. 选择**PEM**单选按钮并复制生成的PEM密钥。
4. 转到**Decoder**选项卡并对PEM进行Base64编码。
5. 返回**JWT Editor Keys**选项卡，单击**New Symmetric Key**。
6. 在对话框中，单击**Generate**以生成一个JWK格式的新密钥。
7. 将生成的`k`参数值替换为你刚刚复制的Base64编码的PEM密钥。
8. 保存该密钥。

### 第 3 步 - 修改你的JWT

一旦有了合适格式的公钥后，你就可以随意修改JWT。只需确保`alg`标头被设置为`HS256`.

### 第 4 步 - 使用公钥签名JWT

使用HS256算法对令牌进行签名，并将RSA公钥作为密钥。

> **实验**
>
> [通过算法混淆绕过JWT认证](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)

## 从现有令牌派生公钥

在公钥不容易获得的情况下，仍然可以通过从一对现有的JWT中派生密钥来测试算法是否混淆。使用诸如`jwt_forgery.py`等工具，这个过程相对简单。你可以在[`rsa_sign2n` GitHub仓库](https://github.com/silentsignal/rsa_sign2n)中找到它以及其他几个有用的脚本。

我们还创建了此工具的简化版本，你可以将其作为单个命令运行：

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

> **注意**
>
> 你需要Docker CLI来运行该工具的任一版本。第一次运行此命令时，它会自动从Docker Hub拉取镜像，这可能需要几分钟时间。

以上操作使用你提供的JWT来计算一个或多个潜在的`n`值。不要太担心这意味着什么，你只需要知道其中只有一个与服务器的密钥所使用的`n`值相匹配。对于每个潜在的值，我们的脚本都会输出：

- 一个以X.509和PKCS1格式的Base64编码的PEM密钥。
- 使用这些密钥中的每一个进行签名的伪造JWT。

要识别正确的密钥，请使用Burp Repeater发送一个包含每个伪造JWT的请求。服务器将只接受其中一个。然后你可以使用匹配的密钥来构造一个算法混淆攻击。


> **实验**
>
> [通过没有暴露密钥的算法混淆绕过JWT认证](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key)

有关此过程更多的信息，以及如何使用标准的`jwt_forgery.py`工具的细节，请参考[仓库](https://github.com/silentsignal/rsa_sign2n)中提供的文档。

> **阅读更多**
>
> 更多的实验，请查看我们关于JWT攻击的其他专题。
>
> [JWT攻击](./README.md)