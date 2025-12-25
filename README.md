# pgvictoria

**pgvictoria** is a tuning solution for [PostgreSQL](https://www.postgresql.org).

**pgvictoria** is named after the Roman Goddess of Speed.

## Features

* PostgreSQL configuration comparison

## Overview

**pgvictoria** makes use of

* Process model
* Shared memory model across processes
* [libev](http://software.schmorp.de/pkg/libev.html) for fast network interactions
* [Atomic operations](https://en.cppreference.com/w/c/atomic) are used to keep track of state

## Tested platforms

* [Fedora](https://getfedora.org/) 42+
* [RHEL 9.x](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9)
* [Rocky Linux 9.x](https://rockylinux.org/)
* [FreeBSD](https://www.freebsd.org/)

## Compiling the source

**pgvictoria** requires

* [clang](https://clang.llvm.org/)
* [cmake](https://cmake.org)
* [make](https://www.gnu.org/software/make/)
* [libev](http://software.schmorp.de/pkg/libev.html)
* [OpenSSL](http://www.openssl.org/)
* [rst2man](https://docutils.sourceforge.io/)
* [pandoc](https://pandoc.org/)
* [texlive](https://www.tug.org/texlive/)

```sh
dnf install git gcc clang clang-analyzer clang-tools-extra cmake make libev libev-devel openssl openssl-devel python3-docutils libatomic libasan libasan-static
```

Alternative [gcc](https://gcc.gnu.org) can be used.

### Release build

The following commands will install **pgvictoria** in the `/usr/local` hierarchy.

```sh
git clone https://github.com/pgvictoria/pgvictoria.git
cd pgvictoria
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_INSTALL_PREFIX=/usr/local ..
make
sudo make install
```

See [RPM](./doc/RPM.md) for how to build a RPM of **pgvictoria**.

### Debug build

The following commands will create a `DEBUG` version of **pgvictoria**.

```sh
git clone https://github.com/pgvictoria/pgvictoria.git
cd pgvictoria
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug ..
make
```

Remember to set the `log_level` configuration option to `debug5`.

## Contributing

Contributions to **pgvictoria** are managed on [GitHub.com](https://github.com/pgvictoria/pgvictoria/)

* [Ask a question](https://github.com/pgvictoria/pgvictoria/discussions)
* [Raise an issue](https://github.com/pgvictoria/pgvictoria/issues)
* [Feature request](https://github.com/pgvictoria/pgvictoria/issues)
* [Code submission](https://github.com/pgvictoria/pgvictoria/pulls)

Contributions are most welcome !

Please, consult our [Code of Conduct](./CODE_OF_CONDUCT.md) policies for interacting in our
community.

Consider giving the project a [star](https://github.com/pgvictoria/pgvictoria/stargazers) on
[GitHub](https://github.com/pgvictoria/pgvictoria/) if you find it useful. And, feel free to follow
the project on [X](https://x.com/pgvictoria/) as well.

## License

[BSD-3-Clause](https://opensource.org/licenses/BSD-3-Clause)
