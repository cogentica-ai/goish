// go: package net/http/fcgi
//
// net/http/fcgi — the FastCGI protocol.
//
// Go splits the package into fcgi.go (the wire protocol: record
// framing, the name/value pair codec) and child.go (the responder that
// turns records into http.Requests). Only child.go depends on
// net/http/cgi; fcgi.go imports nothing goish lacks, which is why the
// protocol layer lands first.
//
// This file is a module root, so it carries no `// go:` anchors —
// GOISH015 reserves those for the files that mirror a Go source file.

#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod child;
pub mod fcgi;

pub use child::{
    addFastCGIEnvToContext, filterOutUsedEnvVars, newChild, newRequest, request, ProcessEnv, Serve,
};
pub use fcgi::{
    bufWriter, conn, encodeSize, newConn, newWriter, readSize, readString, recType, record,
    streamWriter, typeAbortRequest, typeBeginRequest, typeData, typeEndRequest, typeGetValues,
    typeGetValuesResult, typeParams, typeStderr, typeStdin, typeStdout, typeUnknownType,
    writePairs, ReadWriteCloser,
};
