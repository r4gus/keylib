# Platform authenticator reference implementation for Linux

This is a reference implementation I use for testing. It's a little bit hacky but it works.

This impl depends on the following:

* `/dev/uhid` - To create a virtual usb hid interface for the client
* `libnotify` - User interaction (user presence checks)
* [CouchDB](https://docs.couchdb.org/en/stable/install/index.html) - For storing credentials. Please make sure you have CochDB installed

This impl was tested on Ubuntu `22.04`.

## Getting started

1. Install CouchDB on your system (remember your username and password)
2. Download the [Zig 0.11.0 compiler](https://ziglang.org/download/)
3. Run `git clone https://github.com/r4gus/fido2 && cd fido2`
4. Compile the project with `zig build`
5. Run the program with `./zig-out/bin/passkee <password> <couchdb-user> <couchdb-password>`

> The first argument is the password used to encrypt all other data.
