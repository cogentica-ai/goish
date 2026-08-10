// go: package internal/byteorder
//
// Package byteorder provides functions for decoding and encoding
// little and big endian integer types from/to byte slices.

mod byteorder;

pub use byteorder::{
    BEAppendUint16, BEAppendUint32, BEAppendUint64, BEPutUint16, BEPutUint32, BEPutUint64,
    BEUint16, BEUint32, BEUint64, LEAppendUint16, LEAppendUint32, LEAppendUint64, LEPutUint16,
    LEPutUint32, LEPutUint64, LEUint16, LEUint32, LEUint64,
};
