Injection Flaws: Searching for patterns that might indicate SQL injection, command injection, etc.

Dynamic SQL queries: \.query\(\s*["']\s*+\s*`
Command execution: exec\(\s*["']\s*+\s*`
Cross-Site Scripting (XSS): Identifying places where user input might be improperly sanitized before being used in the DOM.

Direct DOM manipulation: innerHTML\s*=\s*
Setting URL redirections or links with user input: location.href\s*=\s*|href\s*=\s*
Insecure Deserialization: Looking for instances where user-provided data is deserialized without adequate safeguards.

Deserialization from user input: JSON\.parse\(\s*.*\s*\)
Use of Hardcoded Credentials: Detecting hardcoded secrets or tokens.

Hardcoded secrets: const\s+.*(password|secret|apiKey)\s*=\s*['"].+['"]
Insecure Use of Dependencies: Finding outdated or vulnerable library imports.

This is better handled by tools like npm audit or Snyk, but you can search for specific library versions: import\s+.*\s+from\s+['"].*@(?!latest)[0-9]+.*['"]
Weak Cryptography: Identifying the use of weak or deprecated cryptographic functions.

Use of weak hash functions: \b(md5|sha1)\s*\(
Insecure random values: Math\.random\(\)
Improper Access Control: Spotting patterns where permissions or sensitive actions might not be adequately checked.

Direct object references without checks: req\.params\.id
Missing or Insecure Headers: Searching for responses that might not include security-enhancing headers.

Lack of security headers: This is context-dependent and might not be easily searchable via regex in TypeScript files but can be reviewed in middleware or server configuration files.
File Upload Vulnerabilities: Identifying unrestricted file upload functionality.

File upload without validation: multer\(\)
Logging Sensitive Information: Detecting patterns where sensitive information might be logged.

Logging potentially sensitive information: console\.log\(\s*.*password.*\s*\)

Unvalidated Redirects and Forwards: Searching for redirects that use user input without validation.

Unvalidated redirects: (response\.redirect\(|window\.location\s*=\s*).*\+\s*
Dangerous File Operations: Identifying potentially unsafe file read or write operations.

Dangerous file reads: fs\.readFileSync\(\s*.*\s*\)
Dangerous file writes: fs\.writeFileSync\(\s*.*\s*\)
Insecure Direct Object References (IDOR): Locating direct object references that might be manipulated.

Direct use of user input in database queries or file operations: \.(find|findOne|readFile)\(\s*req\.params
Excessive Data Exposure: Looking for patterns where too much information might be sent to the client.

Excessive data exposure in API responses: .send\(\s*req\.user\)
Returning entire user objects: .json\(\s*user\s*\)
Missing Rate Limiting: Identifying endpoints that might not implement rate limiting.

This is more about the absence of patterns, such as missing middleware for rate limiting, which might not be easily identified with regex but can be audited in route definitions or middleware configurations.
Use of eval(): Spotting the use of eval() which can lead to security vulnerabilities.

Use of eval: eval\(\s*.*\s*\)
Improper Error Handling: Searching for patterns that might leak sensitive information through error messages.

Sending error details to clients: .send\(\s*err\s*\)
Logging detailed error objects: console\.error\(\s*err\s*\)
Security Misconfiguration: Identifying default configurations that are insecure.

This often requires checking configuration files or code comments for hints of default passwords, unnecessary services, etc., which might not be easily caught with regex patterns.
Using Components with Known Vulnerabilities: Identifying usage of libraries or components known to be vulnerable.

Specific version imports that are vulnerable: import\s+.*\s+from\s+['"].*@2\.1\.3['"]
Again, this is better addressed with dependency analysis tools but can be supplemented with regex searches for known bad versions.
Cross-Site Request Forgery (CSRF): Searching for forms or AJAX calls that might not implement anti-CSRF tokens.

Forms without CSRF tokens: <form.*>.*(?!csrfToken)
AJAX calls missing anti-CSRF headers: $.ajax\(\{.*(?!headers: \{\s*'X-CSRF-TOKEN'
Insecure Forwarding: Looking for use of user input in forwarding or include statements.

Insecure forwarding: res\.forward\(\s*.*\s*\)
Lack of Content Security Policy (CSP): Identifying absence of CSP headers which are crucial for preventing XSS attacks.

Since CSP is usually set in HTTP headers, it's not directly searchable in TypeScript files but should be part of security headers review in server configuration.

Use of Weak or Insecure JWT Libraries: Identifying imports of libraries known for not enforcing strong signatures or validations in JSON Web Tokens.

Importing insecure JWT libraries: import\s+.*\s+from\s+['"]jsonwebtoken['"]
Exposure of Sensitive File Paths: Locating instances where system or application file paths are exposed, either in logs or responses.

Logging file paths: console\.log\(\s*.*(__dirname|__filename).*\s*\)
Exposing file paths in responses: .send\(\s*.*(__dirname|__filename).*\s*\)
Unsafe Cross-Origin Resource Sharing (CORS) Configuration: Detecting overly permissive CORS settings.

Allowing all origins in CORS: cors\(\{\s*origin:\s*['"]\*['"]\s*\}\)
Inadequate Session Timeout or Cookie Handling: Identifying insecure practices in session management, such as long session timeouts or insecure cookie attributes.

Setting cookies without secure attributes: .cookie\(\s*.*,\s*.*,\s*\{.*(?!secure|httpOnly|sameSite).*\}\)
Storage of Credentials in Local Storage: Searching for code that might be storing sensitive information insecurely in browser storage.

Using local storage for sensitive data: localStorage.setItem\(\s*['"](password|token)['"]
Improperly Configured Security Headers: Identifying missing or misconfigured HTTP security headers which are crucial for securing web applications.

This is more related to server configuration than TypeScript code but can sometimes be set or recommended within application code comments or documentation.
Unsafe Redirects with User Input: Identifying dynamic redirects that use user input without proper validation, leading to open redirect vulnerabilities.

Unsafe dynamic redirects: res.redirect\(\s*req.query.url\s*\)
Lack of Input Sanitization in API Endpoints: Spotting endpoints that may accept user input without proper sanitization, leading to various injection vulnerabilities.

Direct use of user input in API endpoints: req.body.*\s*\+\s*
Lack of sanitization middleware: Comments or code indicating absence of validation/sanitization for user inputs.
Insecure Integration of Third-party Services: Identifying code snippets that integrate with third-party services without proper security measures, such as lacking validation of input/output data.

Hardcoded API keys for third-party services: ['"]api_key['"]\s*:\s*['"].*['"]
Ignoring Security Updates or Notices: Comments or TODOs in code that indicate postponed security updates or ignored security recommendations.

Ignoring security update TODOs: //\s*TODO:\s*update\s*this\s*library\s*for\s*security\s*reasons
Use of Deprecated or Unsafe Node.js Functions: Identifying the use of Node.js functions that are deprecated or known to be unsafe.

Use of deprecated Node.js functions: require\(\s*['"](crypto|url|querystring)['"]\s*\)\.\s*(parse|createCipher)
Failure to Validate SSL/TLS Certificates: Spotting instances where SSL/TLS certificate validation might be disabled or mishandled, particularly in HTTP requests to external services.

Disabling SSL/TLS certificate validation: { rejectUnauthorized: false }

Direct Use of Document or Window Objects: Identifying direct manipulations that could lead to DOM-based XSS or other client-side vulnerabilities.

Direct manipulation of document or window: document\.(getElementById|querySelector)\( or window\.(location|open)\(
Improper Handling of JWT Tokens: Looking for insecure practices in handling JWTs, such as not verifying the signature or sensitive data exposure.

Not verifying JWT signature: jwt.decode\( (without a subsequent verify step)
Storing JWT in LocalStorage: localStorage\.(setItem|getItem)\(\s*['"]jwt['"]
Usage of Inline Scripts or eval-like Methods: Searching for the use of inline scripts or methods similar to eval(), which can execute arbitrary code and lead to XSS attacks.

Using new Function() or similar to eval: new Function\( or setTimeout\( or setInterval\( with strings that concatenate variables
Insecure WebSocket Connections: Identifying WebSocket connections that do not use secure protocols (wss://).

Insecure WebSocket connection: new WebSocket\(\s*['"]ws:
Lack of CSP (Content Security Policy) Implementations: While CSP is often configured server-side, identifying client-side code that suggests or requires CSP can be beneficial for security posture.

Suggestions or requirements for CSP in comments: //.*CSP
Insecure Use of RegEx: Identifying potentially vulnerable regular expressions that could lead to Regular Expression Denial of Service (ReDoS) attacks.

Complex or nested quantifiers that may cause catastrophic backtracking: \(.+\)+.*\{.*\}
Unsafe Handling of User Uploaded Files: Searching for code patterns that handle file uploads without adequate security checks, potentially leading to arbitrary file upload vulnerabilities.

File upload without validation: multer\(\s*\) or FormData\(\).append\( without subsequent file type or size validation
Ignoring HTTPS for Sensitive Communications: Identifying instances where sensitive data might be transmitted over insecure channels.

Hardcoded HTTP URLs in data transmission: fetch\(\s*['"]http:\/\/
Use of Non-Secure Third-Party Scripts: Spotting the inclusion of third-party scripts over insecure channels or without integrity checks.

Including third-party scripts without HTTPS or integrity attributes: <script src="http:\/\/
Misconfigured or Absent Security Headers in Client-Side Fetch/AJAX Calls: Identifying fetch or AJAX calls that lack necessary security headers.

Fetch or AJAX calls missing security headers: fetch\(\s*.*,\s*\{.*(?!headers: \{.*'Content-Security-Policy').*\}\)
Failure to Use Asynchronous Cryptography Properly: Identifying potential misuse of cryptographic functions, particularly asynchronous ones, that might lead to blocking the event loop or vulnerabilities.

Misuse of crypto functions: crypto\.createCipher\( or crypto\.randomBytes\( without proper asynchronous handling
Omitting Encryption for Sensitive Data in Transit or At Rest: Identifying patterns where sensitive data may be handled or stored without proper encryption.

Handling or storing sensitive data without mentioning encryption: localStorage.setItem\(, sessionStorage.setItem\(, or direct database insertions without encryption comments
Insecure Direct Interaction with the DOM: Identifying patterns that suggest direct DOM manipulation which could be better served with safer, framework-provided methods.

Unsafe direct DOM interactions: .innerHTML = or .outerHTML = without sanitization
Use of Obsolete Web Technologies: Identifying usage of technologies or methods that are considered obsolete and potentially insecure.

Usage of obsolete methods or properties: document.write\( or element.attachEvent\(
Lack of Proper Session Management: Identifying code that suggests improper session management, such as manual handling of session tokens.

Manual session token handling: document.cookie = without secure flags or manual token storage in storage APIs
Failure to Implement Proper Error Handling: Identifying inadequate or missing error handling that could lead to information leakage or unreliable application behavior.

Inadequate error handling: .catch\(\s*console\.log\) or error handling that logs sensitive information
