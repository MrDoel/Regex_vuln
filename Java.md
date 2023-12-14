## SQL Injection Vulnerabilities

Find direct usage of `executeQuery` with concatenated strings:
```
\bexecuteQuery\([^)]*\+\s*[^)]*\)
```

Detecting potential SQL injection in PreparedStatement:
```
\bPreparedStatement\s+.*=\s*conn\.prepareStatement\([^)]*\+\s*[^)]*\)
```

```
\bexecuteQuery\([^)]*\+\s*[^)]*\bgetParameter\([^)]*\)[^)]*\)
```
## Cross-Site Scripting (XSS) Vulnerabilities
Finding `getParameter` used directly in output functions (simplified example):
```
\b(getParameter|getParameterValues)\([^)]*\)\s*\+\s*[^;]*
```
## Insecure File Operations
Detecting potential path traversal in file operations:
```
new\s+File\([^)]*\+\s*[^)]*getParameter\([^)]*\)[^)]*\)
```
## Insecure Cryptographic Practices
Detect usage of weak hash functions like MD5 or SHA1:
```
MessageDigest\.getInstance\("MD5"\)|MessageDigest\.getInstance\("SHA1"\)
```

```
Key\s+\w+\s*=\s*["'][^"']+["']
```
## Hardcoded Sensitive Information
Finding hardcoded passwords or keys:
```
(password|passwd|pwd|key)\s*=\s*".+"
```

```
password\s*=\s*["'][^"']+["']
```
## Insecure Network Communication
Detect usage of insecure HTTP URLs:
```
http://[^\s]+
```
## Improper Exception Handling
```
catch\s*\(\s*Exception\s+[^)]*\)
```

## Unsecured Sockets
Detecting unsecured socket creation:
```
new Socket\([^)]*\)
```
## Insecure Random Number Generation
```
new\s+java\.util\.Random\(\)
```

## Detecting potentially unsafe deserialization
```
readObject\(\)
```

## Finding usage of reflection which can be misused
Finding usage of reflection which can be misused:
```
java\.lang\.reflect\.
```

## Identifying hardcoded IP addresses
```
\b\d{1,3}(\.\d{1,3}){3}\b
```

## System Command Execution
Detecting execution of system commands which can be a security risk:
```
Runtime\.getRuntime\(\)\.exec\(
```

## Finding potentially insecure LDAP queries
```
new\s+InitialLdapContext\(
```

## Finding usage of deprecated classes or methods (example for java.security.acl package)
```
java\.security\.acl\.
```

## Identifying hardcoded file paths
```
(C:\\\\[^"]+|/home/[^"]+|/usr/[^"]+)
```
## Insecure Data Storage
```
FileOutputStream\(|FileWriter\(
```

## Insecure Logging of Sensitive Information
Detect logging of sensitive information like passwords or secrets:
```
\.log\([^)]*\b(password|secret|token)\b[^)]*\)
```

## Use of Assert in Production Code:
Find uses of assert which might be disabled in production environments:
```
\bassert\s+
```
## Hardcoded Encryption Keys
Identify hardcoded encryption keys in the code:
```
\bkey\s*=\s*["'][^"']+["']
```
## Insecure HTTP Methods
Detect usage of insecure HTTP methods like TRACE or TRACK
```
setRequestMethod\("TRACE"\)|setRequestMethod\("TRACK"\)
```
## Finding risky usage of setAccessible in Java Reflection API
```
\.setAccessible\(\s*true\s*\)
```
## Identifying usage of insecure hashing algorithms
```
\bMD2\b|\bMD5\b|\bSHA-1\b
```
## Finding cookies not marked as Secure or HttpOnly
```
new\s+Cookie\([^)]*\)\.setHttpOnly\(false\)|new\s+Cookie\([^)]*\)\.setSecure\(false\)
```
## Catching exceptions that might leak system information
```
catch\s*\(\s*Exception\s*e\s*\)\s*\{\s*e\.printStackTrace\(\);
```

```
\.printStackTrace\(
```
## Detect potential command injection via exec method
```
\.exec\([^)]*\+\s*[^)]*\)
```

## Detecting Insecure Serialization
```
writeObject\(|readObject\(
```
## Finding Usage of System Properties
Detecting direct access to system properties, which can be a security risk:
```
System\.getProperty\(
```
## Identifying Weak Encryption Modes
```
Cipher\.getInstance\(".*\/ECB\/.*"\)
```

```
Cipher\.getInstance\(["'][A-Za-z0-9/]+\/ECB\/[A-Za-z0-9/]+["']\)
```
## Detecting Insecure Random Number Generators
```
new\s+Random\(\)
```
## Finding TrustManager That Trusts All Certificates
```
new\s+X509TrustManager\(\s*\{\s*public\s+void\s+checkClientTrusted\(
```
## Detecting Inclusion of External JavaScript
Identifying inclusion of external JavaScript, which can lead to XSS:
```
<script\s+src\s*=\s*["'][^"']+["']
```
## Spotting Disabled SSL Certificate Checking
```
TrustManager\[\s*\]\s*=\s*new\s+TrustManager\[\s*\{\s*new\s+X509TrustManager\(\s*\)\s*\}\s*\]
```
## Finding Hardcoded Timeout Values
Identifying hardcoded timeout values, which can be a sign of poor error handling:
```
.setTimeout\(\s*\d+\s*\)
```
## Detecting Usage of getInsecure
Spotting usage of `getInsecure` method in SSL context:
```
SSLContext\.getInstance\(".*"\)\.getInsecure\(
```
## Finding Use of getRuntime.exec for Command Execution
```
Detecting potential risks with command execution:
```

## Finding Insecure Cookie Handling
Detecting cookies not set with secure attributes:
```
new\s+Cookie\([^)]*\)\s*\.\s*setSecure\s*\(\s*false\s*\)
```
## Detecting Excessive Logging
Identifying potentially excessive or sensitive data logging:
```
\.log\s*\([^)]*\b(password|username|email)\b[^)]*\)
```
## Finding Direct Use of IP Addresses in Network Connections
Spotting direct use of hardcoded IP addresses in network connections:
```
\bconnect\s*\([^)]*\/\/\d{1,3}(\.\d{1,3}){3}\b
```
## Detecting Use of File.separator in File Paths
Identifying potential path traversal issues using `File.separator`:
```
File.separator\s*\+\s*["'][^"']*["']
```
## Finding Deprecated SSL/TLS Protocols
```
SSLContext\.getInstance\("SSLv2"\)|SSLContext\.getInstance\("SSLv3"\)
```
## Detecting Insecure Data Storage Practices
```
FileOutputStream\s*\(|FileWriter\s*\(
```
## Finding Improper Error Handling
Spotting catch blocks that do nothing or suppress exceptions:
```
catch\s*\([^)]*\)\s*\{\s*//?\s*TODO\s*\}
```
## Detecting Insecure External Command Execution
Identifying potential command injection risks:
```
ProcessBuilder\s*\([^)]*\+\s*[^)]*\)
```
## Finding Unchecked Type Casting
Detecting unchecked type casts which could lead to runtime exceptions:
```
\(\s*[A-Za-z0-9_\.]+\s*\)\s*\w+
```
## Detecting Insecure Use of Thread.sleep in Loops
Identifying potential risks with the use of `Thread.sleep` inside loops:
```
while\s*\([^)]*\)\s*\{\s*[^}]*Thread\.sleep\s*\([^)]*\)\s*[^}]*\}
```

## Detecting Hardcoded URL in Network Connections
Identifying hardcoded URLs which might be security-sensitive:
```
new\s+URL\(["'][^"']+["']\)
```
## Finding Use of Default Charset
Detecting cases where the default charset is used, which can lead to issues in internationalization:
```
.getBytes\(\s*\)|.getBytes\(\s*Charset\.defaultCharset\(\s*\)\s*\)
```
## Detecting Direct Use of System.getenv
Identifying direct access to environment variables, which can expose sensitive data:
```
System\.getenv\(
```
## Finding Insecure Cookie Configurations
Identifying cookies set without HttpOnly flag, which can be susceptible to XSS attacks:
```
new\s+Cookie\([^)]*\)\s*\.\s*setHttpOnly\s*\(\s*false\s*\)
```
## Detecting Weak SSL Context TLSv1
```
SSLContext\.getInstance\("TLSv1"\)
```
## Finding Use of exec() with Concatenated Commands
Detecting potential command injection risks via concatenated commands in `exec()`:
```
Runtime\.getRuntime\(\)\.exec\([^)]*\+\s*[^)]*\)
```
## Detecting Hardcoded Sensitive Information in Logs
Identifying logging of sensitive information such as API keys or tokens:
```
\.log\([^)]*\b(api_key|token)\b[^)]*\)
```
## Finding Unencrypted Sockets
Spotting potential unencrypted socket communications:
```
new\s+Socket\(
```
## Detecting Insecure File Paths
Identifying potential insecure file path constructions:
```
new\s+File\([^)]*\+\s*[^)]*\)
```
## Detecting Direct Access to JDBC Connections
Spotting potentially insecure direct JDBC connection creation:
```
DriverManager\.getConnection\(
```

## Detecting Exposed AWS Access Keys
Identifying AWS Access Key IDs and Secret Access Keys in code:
```
(AKIA[0-9A-Z]{16})|(aws_secret_access_key\s*=\s*["'][0-9a-zA-Z/+]{40}["'])
```
## Finding Exposed API Keys
```
api_key\s*=\s*["'][0-9a-zA-Z]{32,45}["']
```
## Detecting Weak Cryptographic Algorithms
```
\b(DES|RC2|RC4|MD4|MD5)\b
```
## Finding Hardcoded Credentials
```
(username\s*=\s*["'][^"']+["'])|(password\s*=\s*["'][^"']+["'])|(token\s*=\s*["'][^"']+["'])
```
## Finding Hardcoded JDBC URLs
Spotting hardcoded JDBC connection strings, which can indicate database credentials or server details:
```
jdbc:mysql:\/\/[^\s:]+:[^\s@]+@[^\s:]+:\d+\/[^\s]+
```

## Detecting Non-Constant Static Fields
Identifying non-final static fields, which might be a thread safety concern:
```
static\s+(?!final)\w+\s+\w+;
```
## Detecting Dynamic Class Loading
Identifying dynamic class loading, which can be a security risk if not properly handled:
```
Class\.forName\(\s*["'][^"']+["']\s*\)
```
## Detecting Unprotected Singleton Instances
Identifying potential thread safety issues with Singleton implementations:
```
public\s+(static\s+)?[A-Za-z0-9_]*\s+instance;
```
## Finding Use of java.io.File for File Paths
Identifying direct use of `java.io.File`, which might be prone to path traversal attacks:
```
new\s+File\([^)]*\)
```

## Detecting Usage of Default Security Providers
Identifying usage of default security providers, which can be insecure:
```
getInstance\(["'][^,)]+["']\)
```

## Detecting Hardcoded Encryption Keys
Identifying hardcoded encryption keys, which is a security risk:
```
SecretKeySpec\([^,]+,\s*["']AES["']\)
```

## Finding Potential JDBC SQL Injection Vulnerabilities
Identifying potential SQL injection vulnerabilities in JDBC operations:
```
executeQuery\([^)]*\+\s*[^)]*\)
```

## Detecting Use of Deprecated Java Security Classes
Identifying usage of deprecated classes in `java.security` package:
```
java\.security\.[a-zA-Z0-9_]+\.getInstance\(
```

## Finding Usage of System.out.print() for Debugging
Spotting usage of `System.out.print` or `System.out.println`, which could be leftover debug code:
```
System\.out\.(print|println)\(
```
## Detecting Lack of SSL/TLS Hostname Verification
Identifying potential lack of hostname verification in SSL/TLS connections:
```
HttpsURLConnection\.setDefaultHostnameVerifier\(
```
## Detecting Direct Use of Executors
Spotting direct usage of executors, which could lead to unmanaged thread creation:
```
Executors\.new
```
## Finding Non-Transactional Database Operations
Spotting database operations outside of transactional contexts:
```
\.createStatement\(\)\.(execute|executeQuery|executeUpdate)\(
```

## Detecting Unchecked Reflection Calls
Identifying unchecked or potentially unsafe reflection method invocations:
```
\.getMethod\(["'][^"']+["'],\s*[^)]+\)\.invoke\(
```
## Finding Insecure Temporary File Creation
Spotting potentially insecure temporary file creation:
```
File\.createTempFile\(
```
## Detecting Usage of Default Charset in String Conversions
Identifying String conversions that rely on the platform's default charset:
```
new\s+String\([^,]+?\)|\.getBytes\(\s*\)
```
## Finding Direct Access to HTTPServletRequest Objects
Spotting direct access to `HTTPServletRequest` objects, which might lead to security issues like header injection:
```
HttpServletRequest\s+\w+\s*=\s*
```

Identifying direct use of thread methods in servlets, which can lead to thread safety issues:
```
HttpServlet\{[^}]*\b(new\s+Thread\(|\.start\(\)|\.run\(\))
```
## Detecting Unvalidated Redirects and Forwards
Identifying unvalidated redirects or forwards, leading to potential URL redirection attacks:
```
response\.sendRedirect\(\s*[^)]+\s*\)
```
## Detecting Misuse of finalize Method
Spotting potential misuse of the `finalize` method, which can be a source of security issues:
```
protected\s+void\s+finalize\(\)
```

## Detecting Usage of Deprecated Java API
Identifying usage of deprecated Java API methods or classes:
```
\@Deprecated
```

## Detecting Insecure Loading of Properties Files
Identifying potentially insecure loading of properties files, which might lead to information disclosure:
```
Properties\(\)\.load\(
```

## Detecting Direct Instantiation of HttpClient
Finding direct instantiations of `HttpClient`, which might not be using best security practices:
```
new\s+HttpClient\(
```
## Finding Hardcoded User Agents
Spotting hardcoded user agent strings in HTTP requests, which can be a sign of inflexible code:
```
setUserAgent\(["'][^"']+["']\)
```
## Detecting Usage of Java Swing Components (Potential UI Security Flaws)
Identifying use of Java Swing components, which might be relevant for UI security reviews:
```
javax\.swing\.
```
## Finding Potential Use of Insecure Data Transfer Protocols
```
(ftp:\/\/)
```

## Detecting Direct Use of DocumentBuilderFactory without Secure Processing
Identifying potential XML External Entity (XXE) vulnerabilities:
```
DocumentBuilderFactory\.newInstance\(\)\.(?!.*setFeature\("http://javax\.xml\.XMLConstants/feature/secure-processing",\s*true\))
```
## Detecting Inclusion of External Scripts in JSP/JSF
Identifying external script inclusions in Java web pages, which can be a vector for XSS attacks:
```
<script.*src\s*=\s*["'][^"']*["'].*<\/script>
```
## Finding Unchecked Calls to loadLibrary/load
Spotting potentially unsafe calls to `System.loadLibrary` or `System.load`:
```
System\.loadLibrary\(|System\.load\(
```

## Detecting Insecure File Permissions

```
new\s+FilePermission\(["'][^"']*["'],\s*["']write["']\)
```
## Finding Usage of Obsolete Collection Classes
Spotting usage of obsolete or less efficient collection classes like Vector or Hashtable:
```
new\s+(Vector|Hashtable)\<
```



