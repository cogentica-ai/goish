// go: package crypto/internal/fips140deps/byteorder

mod byteorder;

pub use byteorder::{
    BEAppendUint16, BEAppendUint32, BEAppendUint64, BEPutUint16, BEPutUint32, BEPutUint64,
    BEUint32, BEUint64, LEPutUint64, LEUint16, LEUint64,
};
