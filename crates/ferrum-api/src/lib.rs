//! Kubernetes API FERRUM (`ferrum.io/v1`).
//!
//! Типы сериализуются в те же YAML, что уйдут в CRD.
//! `#[kube(group = "ferrum.io", version = "v1", kind = "...")]` подключается
//! фичей `kube-derive` на toolchain >= 1.85. Здесь, на 1.75, макрос не собираем:
//! транзитивные crate уже требуют edition2024. Архитектор, который «просто
//! обновит nightly в проде ради derive», пусть сначала подпишет риск.

mod types;

pub use types::*;

pub const GROUP: &str = "ferrum.io";
pub const VERSION: &str = "v1";
