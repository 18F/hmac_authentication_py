# hmac_authentication Python package

Signs and validates HTTP requests based on a shared-secret HMAC signature.

Developed in parallel with the following packages for other languages:
- Go: [github.com/18F/hmacauth](https://github.com/18F/hmacauth/)
- Ruby: [hmac_authentication](https://rubygems.org/gems/hmac_authentication)
- Node.js: [hmac-authentication](https://www.npmjs.com/package/hmac-authentication)

## Installation

```sh
$ pip install hmac-authentication
```

## Validating incoming requests

Inject something resembling the following code fragment into your request
handling logic as the first thing that happens before the request body is
parsed, where `headers` is a list of headers factored into the signature and
`secret_key` is the shared secret between your application and the service
making the request:

_...coming soon..._

## Signing outgoing requests

_...coming soon..._

## Running tests

```sh
$ pip install nose
$ nosetests
```

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
