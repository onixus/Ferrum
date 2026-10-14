# kube-client 1.1.0 YAML dependency backport

Upstream: https://github.com/kube-rs/kube, crates.io kube-client 1.1.0.
Original archive SHA-256: `7cb276b85b6e94ded00ac8ea2c68fcf4697ea0553cb25fddc35d4a0ab718db8d`. Apache-2.0; upstream LICENSE retained.

Upstream commit: `1ba4b2ad63bddd21d43c9c0c3f40078ec2b05922`. LICENSE is copied from that exact upstream commit.

Only the serde_yaml dependency in Cargo.toml and Cargo.toml.orig is redirected
to maintained serde_norway 0.9.42, under the original serde_yaml Rust import name.
All implementation sources remain byte-identical to the published crate.
This removes deprecated serde_yaml and unmaintained unsafe-libyaml from the
Kubernetes client path without changing kube 1.1 APIs or Ferrum CRD serialization.
The ordinary advisories/license/source gates remain enabled.

Remove this patch when upgrading kube to a release whose config parser no longer
uses deprecated serde_yaml. Do not turn this directory into an independent client fork.
