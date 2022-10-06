# XML外部实体（XXE）注入

在本节中，我们将解释什么是XML外部实体注入，描述一些常见的示例，解释如何发现和利用各种XXE注入，并总结如何防止XXE注入攻击。

## 什么是XML外部实体注入？

XML外部实体注入（也称为XXE）是一个web安全漏洞，它使攻击者能够干扰应用程序对XML数据的处理。 它通常使攻击者可以查看应用程序服务器文件系统上的文件，并与应用程序本身可以访问的任何后端或外部系统进行交互。

在某些情况下，攻击者可以利用XXE漏洞执行服务器端请求伪造（SSRF）攻击，从而升级XXE攻击，以破坏底层服务器或其他后端基础结构。

![](../../.gitbook/assets/image%20%285%29.png)

## XXE漏洞如何产生？

一些应用程序使用XML格式在浏览器和服务器之间传输数据。 实际上，执行此操作的应用程序始终使用标准库或平台API来处理服务器上的XML数据。 XXE漏洞的出现是因为XML规范包含各种潜在的危险功能，即使应用程序通常不使用这些功能，标准解析器也支持这些功能。

XML外部实体是一种自定义XML实体，其定义值是从声明它们的DTD外部加载的。 从安全角度来看，外部实体特别有趣，因为外部实体允许基于文件路径或URL的内容定义实体。

## XXE攻击有哪些类型？

XXE攻击有多种类型：

* 利用XXE来检索文件，其中定义了一个包含文件内容的外部实体，并在应用程序的响应中返回。
* 利用XXE执行SSRF攻击，其中基于到后端系统的URL定义外部实体。
* 利用盲目的XXE泄漏带外数据，其中敏感数据从应用程序服务器传输到攻击者控制的系统。
* 利用盲目的XXE通过错误消息检索数据，攻击者可以在其中触发包含敏感数据的解析错误消息。

## 利用XXE检索文件

要执行从服务器的文件系统中检索任意文件的XXE注入攻击，您需要以两种方式修改提交的XML：

* 引入（或编辑）一个DOCTYPE元素，该元素定义一个包含文件路径的外部实体。
* 编辑应用程序响应中返回的XML中的数据值，以利用已定义的外部实体。

例如，假设购物应用程序通过将以下XML提交给服务器来检查产品的库存水平：

```text
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>381</productId></stockCheck>
```

该应用程序没有针对XXE攻击的特殊防御措施，因此您可以通过提交以下XXE有效负载来利用XXE漏洞来检索/ etc / passwd文件：

```text
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><stockCheck><productId>&xxe;</productId></stockCheck>
```

此XXE有效负载定义了一个外部实体＆xxe;。 其值是/ etc / passwd文件的内容，并使用productId值内的实体。 这将导致应用程序的响应包括文件内容：

```text
Invalid product ID: root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologin...
```

#### 注意

借助实际的XXE漏洞，提交的XML中通常会存在大量数据值，其中任何一个都可以在应用程序的响应中使用。 为了系统地测试XXE漏洞，通常将需要通过使用定义的实体并查看其是否出现在响应中来分别测试XML中的每个数据节点。

**实验室**使用外部实体来利用XXE来检索文件

## 利用XXE执行SSRF攻击

除了检索敏感数据外，XXE攻击的另一个主要影响是，它们可用于执行服务器端请求伪造（SSRF）。 这是一个潜在的严重漏洞，其中可能导致服务器端应用程序对服务器可以访问的任何URL发出HTTP请求。

要利用XXE漏洞执行SSRF攻击，您需要使用要定位的URL定义外部XML实体，并在数据值中使用定义的实体。 如果您可以在应用程序响应中返回的数据值中使用已定义的实体，那么您将能够从应用程序响应中的URL查看响应，从而与后端系统进行双向交互。 如果没有，那么您将只能执行盲目SSRF攻击（仍然可能会产生严重后果）。

在下面的XXE示例中，外部实体将使服务器向组织的基础结构内的内部系统发出后端HTTP请求：

```text
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

**实验室**利用XXE执行SSRF攻击

## XXE盲漏洞

XXE漏洞的许多实例都是盲目的。 这意味着应用程序不会在其响应中返回任何已定义外部实体的值，因此不可能直接检索服务器端文件。

仍然可以检测和利用XXE盲漏洞，但是需要更高级的技术。 有时您可以使用带外技术来发现漏洞并利用它们来窃取数据。 而且您有时可以触发XML解析错误，从而导致错误消息中的敏感数据泄露。

## 寻找用于XXE注入的隐藏攻击面

在许多情况下，XXE注入漏洞的攻击面很明显，因为应用程序的常规HTTP流量包括包含XML格式数据的请求。 在其他情况下，攻击面不太明显。 但是，如果在正确的位置查看，则会在不包含任何XML的请求中发现XXE攻击面。

### XInclude 攻击

一些应用程序接收客户端提交的数据，将其在服务器端嵌入到XML文档中，然后解析该文档。 将客户端提交的数据放入后端SOAP请求中，然后由后端SOAP服务处理该请求时，就会发生这种情况。

在这种情况下，您无法进行经典的XXE攻击，因为您无法控制整个XML文档，因此无法定义或修改DOCTYPE元素。 但是，您可能可以改用XInclude。 XInclude是XML规范的一部分，该规范允许从子文档中构建XML文档。 您可以在XML文档的任何数据值中放置XInclude攻击，因此可以在仅控制放置在服务器端XML文档中的单个数据项的情况下执行攻击。

要执行XInclude攻击，您需要引用XInclude命名空间，并提供要包含的文件的路径。 例如：

```text
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**实验室**利用XInclude检索文件

### 通过文件上传进行XXE攻击

一些应用程序允许用户上传文件，然后在服务器端进行处理。 一些常见的文件格式使用XML或包含XML子组件。 基于XML格式的示例是Office文档格式（例如DOCX）和图像格式（例如SVG）。

例如，一个应用程序可能允许用户上传图像，并在上传后在服务器上处理或验证这些图像。 即使应用程序希望接收PNG或JPEG之类的格式，所使用的图像处理库也可能支持SVG图像。 由于SVG格式使用XML，因此攻击者可以提交恶意的SVG映像，因此可以隐藏攻击面以发现XXE漏洞。

**实验室**通过上传图像文件来利用XXE

### 通过修改的内容类型进行XXE攻击

大多数POST请求都使用HTML表单生成的默认内容类型，例如application / x-www-form-urlencoded。 一些网站希望以这种格式接收请求，但会容忍其他内容类型，包括XML。

例如，如果正常请求包含以下内容：

```text
POST /action HTTP/1.0Content-Type: application/x-www-form-urlencodedContent-Length: 7foo=bar
```

然后，您可以提交以下请求，结果相同：

```text
POST /action HTTP/1.0Content-Type: text/xmlContent-Length: 52<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

如果应用程序允许消息正文中包含XML的请求，并将正文内容解析为XML，则只需重新格式化请求以使用XML格式，就可以到达隐藏的XXE攻击面。

## 如何查找和测试XXE漏洞

使用Burp Suite的web漏洞扫描程序可以快速可靠地找到绝大多数XXE漏洞。

手动测试XXE漏洞通常涉及：

* 通过基于众所周知的操作系统文件定义外部实体并在应用程序响应中返回的数据中使用该实体来测试文件检索。
* 通过基于您控制的系统的URL定义外部实体并监视与该系统的交互，来测试XXE盲目漏洞。 Burp Collaborator客户非常适合此目的。
* 通过使用XInclude攻击来尝试检索众所周知的操作系统文件，以测试用户提供的非XML数据是否容易包含在服务器端XML文档中。

## 如何预防XXE漏洞

实际上，所有XXE漏洞的产生都是因为应用程序的XML解析库支持应用程序不需要或不打算使用的潜在危险XML功能。 防止XXE攻击的最简单、最有效的方法是禁用这些功能。

通常，禁用外部实体的解析并禁用对XInclude的支持就足够了。 通常，这可以通过配置选项或以编程方式覆盖默认行为来完成。 有关如何禁用不必要功能的详细信息，请查阅XML解析库或API的文档。
