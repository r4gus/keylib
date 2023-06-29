# Cbor Key Store

This folder contains code for a password-/ key-store. The store allows the
storage of secrets like passwords or secret-keys, together with other
related data.

> __WARNING__: This is a first draft!

Data layout after serialization using `seal()`: `SECRET || len(OUTER_HEADER) || OUTER_HEADER || TAG || ChaCha20(DATA)`
