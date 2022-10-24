# Jenkins JWT Auth plugin

## Introduction

The JWT Auth plugin allows the authentication of users via an upstream component (one could
be [pomerium](https://www.pomerium.io/)) that provides user information (username and groups)
via an [JWT](https://jwt.io) header that is passed to it.

It consists of a `SecurityRealm` that identifies the user using that header and supports various
configuration options.

Once the plugin is active, all requests are assumed to contain the JWT header. If the header
is not present or the token can not be decoded (and optionally verified), the request is assumed
to be the anonymous user.

The plugin allows to
* Specify which header contains the JWT
* It have a "bearer " prefix or not, both is accepted
* The mapping of username and group list to the claims can be customized (you can choose which claims to read)
* Define a JWKS URL to verify the token. JWKS allows key rotation as needed.

Currently, JWKS is the only way to verify a token.

### A word of caution

Be advised to read all documentation what JWTs are and what not. Do not expose Jenkins with this
plugin enabled directly to the outside world. Jenkins needs to be behind some trusted reverse proxy
that correctly implements the JWT token generation and does not allow outside users to override it.

Additionally, the plugin allows to setup the authentication without token signing and even tolerate
invalid tokens. Be sure to read the inline documentation to all configuration parameters.

## Getting started

After installation, you can go to `Manage Jenkins` -> `Configure Global Security` -> `Security Realms`
where you see the plugin as an option.

![logo](/assets/plugin.png)

Read through all configuration parameters, they are all documented.

## CasC (Configuration as Code) support

This plugin aims to support [Jenkins CasC (JCasC)](https://github.com/jenkinsci/configuration-as-code-plugin).

If you want to configure the SecurityRealm via CasC; [check the example configuration in our tests](https://github.com/jenkinsci/jwt-auth-plugin/blob/develop/src/test/resources/configuration-as-code.yml).

## Issues

Report issues and enhancements in the [Github issue tracker](https://github.com/jenkinsci/jwt-auth-plugin/issues).

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

### Developer notes

Keeping up to date with parent:

* Confirm that you are using the [current parent](https://www.jenkins.io/doc/developer/plugin-development/updating-parent/) pom with the command mvn versions:update-parent
* Locate the most recent plugin bom version number on the plugin bom releases page
* Copy the dependencyManagement section from the pom.xml file in that directory
* Insert this dependencyManagement section into the pom.xml file for your plugin

Releasing

* Label all PRs for [release drafter](https://github.com/jenkinsci/.github/blob/master/.github/release-drafter.adoc) 

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)

