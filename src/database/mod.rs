// database — `database/...` package tree.
//
// Goish v1 ships only the type aliases that downstream ports need
// (e.g., Masterminds/semver/v3's `Version.Value() (driver.Value, error)`
// SQL-driver hook). The full `database/sql` query/connection surface
// isn't ported — anything beyond type-level stubs would pull in the
// driver registry, prepared-statement runtime, etc., which no port has
// asked for yet.

#![allow(non_snake_case)]

pub mod sql;
