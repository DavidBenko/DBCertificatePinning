DBCertificatePinning
====================

Overview
---------

SSL Certificate/Public Key Pinning for iOS to protect against Man-in-the-Middle attacks. This is a proof of concept at the moment, but will be updated for production use.

### Installation

##### Manual Installation
- Add `DBCertificatePinning` and `DBURLConnection` classes to your project
- Import header (`#import "DBCertificatePinning.h"`)

### Pull X.509 SSL Certificate
- Run the following commands to pull a .der certificate from an existing web site.

```shell
openssl s_client -showcerts -connect www.example.com:443 < /dev/null | openssl x509 -outform DER > certificate.der
```

Pinning
---------

### Using Bundled X.509 Certificate (.der)
```shell

NSString *keyPath = [[NSBundle mainBundle] pathForResource:@"certificate"
ofType:@"der"];

[DBCertificatePinning pinDomain:@"example.com" toCertificateAtPath:keyPath];

NSURLRequest *request = [[NSURLRequest alloc]initWithURL:[NSURL URLWithString:@"https://example.com"]];
[DBCertificatePinning executePinnedConnectionForRequest:request];

```

You can pin multiple certificates and domains by calling `pinDomain:toCertificateAtPath` multiple times.


Options
---------

### Connection Allow Policy
You can use the `setAllowPolicy:` method to change the allowance policy for SSL connections.
- `DBCertifcatePinningAllowPolicyOnlyPinned` only allows SSL connections which have been pinned successfully.
- `DBCertifcatePinningAllowPolicyAll` will pin SSL connections which have been registered with `pinDomain:toCertificateAtPath`, but allow any unregistered domains without pinning.

### Pinning Type
You can use the `setPinType:` method to change the type of pinning that will be used.
- `DBCertifcatePinningPinTypePublicKey` will pin the remote server's public key.
- `DBCertifcatePinningPinTypeCertificate` will pin the remote server's certificate.


License
---------------

The MIT License (MIT)

Copyright (c) 2015 David Benko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
