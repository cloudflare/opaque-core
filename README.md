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

## How to Cite

To cite OPAQUE-core, use one of the following formats and update with the date
you accessed this project.

APA Style

```
Bradley, T. and Celi, S. (2020). Introducing OPAQUE-core:
A Proof of Concept implementation of OPAQUE main functionality. Cloudflare.
Available at https://github.com/cloudflare/opaque-core. Accessed Feb 2021.
```

Bibtex Source

```bibtex
@manual{circl,
  title        = {Introducing OPAQUE-core: A Proof of Concept implementation of OPAQUE main functionality},
  author       = {Tatiana Bradley and Sof\'{i}a Celi},
  organization = {Cloudflare},
  note         = {Available at \url{https://github.com/cloudflare/opaque-core}. Accessed Feb 2021},
  month        = dec,
  year         = {2020}
}
```

## License

The project is licensed under the [BSD-3-Clause License](LICENSE).
