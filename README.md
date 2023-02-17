# fido2 authenticator library

![GitHub](https://img.shields.io/github/license/r4gus/ztap?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/r4gus/ztap/CI?style=flat-square)

> _Warning_: NOT PRODUCTION READY!

## Getting started

Just add the library to your project and then call `pull-deps.sh` to pull
all dependencies.

## Examples

| Platform | Architecture | Link |
|:--------:|:------------:|:----:|
| ATSAMD51 Curiosity Nano | Arm | [candy-stick](https://github.com/r4gus/candy-stick) |
| nRF52840-MDK USB Dongle | Arm | [candy-stick](https://github.com/r4gus/candy-stick-nrf) |

## Supported commands

| command           | supported? |
|:-----------------:|:----------:|
| `authenticatorMakeCredential`     | ✅ |
| `authenticatorGetAssertion`       | ✅ |
| `authenticatorGetNextAssertion`   |    |
| `authenticatorGetInfo`            | ✅ |
| `authenticatorClientPin`          | 🏃 |
| `authenticatorReset`              | ✅ |
| `authenticatorBioEnrollment`      |    |
| `authenticatorCredentialManagement` |    |
| `authenticatorSelection`          |    |
| `authenticatorLargeBlobs`         |    |
| `authenticatorConfig`             |    |

## Crypto

TODO: rewrite this section
