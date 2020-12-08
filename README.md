![OPAQUE logo](opaque.png)
# opaque-core

This project is a proof-of-concept implementation
of [OPAQUE](https://github.com/cfrg/draft-irtf-cfrg-opaque/), written
in Go.

**DISCLAIMER**: This is a reference implementation only. **DO NOT** use in
production systems.

## Getting started

Get the source code:

```sh
git clone https://github.com/cloudflare/opaque-core
```

## Running tests

From the `opaque-core` folder, run all tests:

```sh
make test
```

## Usage

For handling an OPAQUE registration, you can use the functions exposed on the
registration.go file.
For handling an OPAQUE login, you can use the functions exposed on the
request.go file.
The marshaling and unmarshaling of messages can be found on the core_messages.go,
request_messages.go and register_messages.go respectively.
A json encoding of messages can be found on the json_encoding.go file.

## License

The project is licensed under the [BSD-3-Clause License](LICENSE).
