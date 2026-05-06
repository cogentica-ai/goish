// database/sql/driver — minimal types from Go 1.25
// `src/database/sql/driver/driver.go`.
//
// Just enough surface so user ports that implement the
// `Valuer`/`Scanner` interfaces (e.g. semver's `Version.Value()`) can
// name `driver.Value` as a return type.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::sync::Arc;
use core::any::Any;

/// Go: `type Value any` (driver.go:62). The dynamic type a database
/// driver hands back to / receives from the SQL layer. In Goish that
/// maps to our usual `Arc<dyn Any + Send + Sync>` interface{} stand-in.
pub type Value = Arc<dyn Any + Send + Sync>;
