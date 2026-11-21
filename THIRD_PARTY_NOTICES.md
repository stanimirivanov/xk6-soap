# Third-party software notices

The xk6-soap source is available under Apache-2.0. [Project license](LICENSE)

The custom executable also includes k6 and the Go runtime. k6 is distributed
under AGPL-3.0. The combined custom binary uses AGPL-3.0 terms, included as
`LICENSE` in the binary archive. `LICENSE.xk6-soap` records the extension's
Apache-2.0 source license. The Go toolchain includes its own license and patent
grant.
[k6 license at the supported pin](https://github.com/grafana/k6/blob/v2.4.0/LICENSE.md) ·
[Go license](https://go.dev/LICENSE)

The release rehearsal records each module actually linked into the binary,
including its version, Go source checksum and the root license, copyright,
patent and notice files found in its verified module source. This covers
runtime dependencies such as Sobek, the XML/XML-security and XPath libraries,
and the PKCS#12 decoder. The archive includes the Go license and patent file.
The Prometheus Protocol Buffers module
`buf.build/gen/go/prometheus/prometheus/protocolbuffers/go` at
`v1.36.12-20261001224011-d7f6cfecf2b8.2` carries Apache-2.0 notices in the
generated Go sources. Copyright 2013, 2016, 2017 and 2024 Prometheus Team.
The archive includes a separate attribution and Apache-2.0 license for that
module because its module root has neither file. Review other missing root
notices before staging an archive.

The independently pinned Apache, Maven, Jetty and JDK test fixture and build
tools are separate from the executable inventory. Review them separately if
distributing their artifacts. [Fixture pins](test/interop/README.md)

Before any custom binary distribution, check component-specific notices and
source obligations, including the corresponding source for the k6-based
binary. The rehearsal pairs a corresponding-source archive with each binary
archive and records their checksums. The workflow retains only metadata and
checksums.
[Release checklist](docs/release.md)
