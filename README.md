# SAML Assertion verification via LDAP

## Overview

This project implements a **fake LDAP server** designed to facilitate SAML authentication. My main use-case for this is SOGo with Dovecot as its mail backend. While SOGo supports SAML, Dovecot does not, necessitating this custom solution. The fake LDAP server validates SAML assertions and mimics LDAP authentication, allowing seamless integration with Dovecot's `passdb` configuration.

## Features

- **SAML Assertion Handling**: Validates SAML assertions received from SOGo.
- **LDAP Compatibility**: Mimics LDAP behavior, allowing Dovecot to authenticate users using the fake LDAP server.
- **Custom Key Store**: Option to use X.509 certificate and private key for secure communication.

## Prerequisites

- Valid SAML Identity Provider (IdP) metadata

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/ldap-saml-assertions.git
   cd ldap-saml-assertions
   ```

2. Build the application:

   ```bash
   go build -o ldap-saml-assertions
   ```

3. Configure the application by creating a configuration file or by passing arguments directly.

## Usage

Run the server with the following command:

```bash
./ldap-saml-assertions sp_cert=/path/to/sp-cert.pem sp_key=/path/to/sp-key.pem [other_arguments]
```

### Command-Line Arguments

- `userid`: Attribute of the username within the SAML assertion.
- `sp_cert`: Path to the SP X.509 certificate file.
- `sp_key`: Path to the SP private key file.
- `idp`: URL or path to the IdP metadata XML.

### Example

To run the server with a certificate and key:

```bash
./ldap-saml-assertions sp_cert=/etc/ssl/certs/sp-cert.pem sp_key=/etc/ssl/private/sp-key.pem idp=https://example.com/idp/metadata.xml
```

## Dovecot Configuration

To configure Dovecot to use this fake LDAP server, you can add the following lines to your Dovecot configuration (`dovecot.conf`):

```conf
passdb {
  driver = ldap
  args = /path/to/your/ldap.conf
}
```

### Sample `ldap.conf` for Dovecot

```conf
hosts = localhost:3389
ldap_version = 3
auth_bind = yes
```

Make sure to replace the placeholders with actual values relevant to your setup.

## Testing the LDAP Server

To test the LDAP server, you can use the `ldapsearch` command as follows:

```bash
ldapsearch -x -H ldap://localhost:3389 -D "<uid>" -w "<base64 encoded SAML assertion>"
```

Replace `<uid>` with the actual username you want to test.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.
