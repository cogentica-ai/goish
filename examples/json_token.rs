#![no_std]
#![no_main]

extern crate alloc;

use goish::encoding::json;
use goish::fmt;
use goish::{bytes, nil, string};

#[goish::main]
fn main() {
    let data = bytes::NewReader(b"{\"name\":\"alice\",\"age\":30,\"items\":[1,2,3]}");
    let mut dec = json::NewDecoder(data);

    loop {
        let (tok, err) = dec.Token();
        if err != nil {
            break;
        }
        match tok {
            json::Token::Delim(d) => {
                fmt::Println!(
                    "Delim:",
                    string::__from_vec(alloc::vec::Vec::from(&[d.as_byte()]))
                );
            }
            json::Token::String(s) => {
                fmt::Println!("String:", s);
            }
            json::Token::Number(n) => {
                let s = goish::strconv::FormatFloat(n, 'f' as u8, -1, 64);
                fmt::Println!("Number:", s);
            }
            json::Token::Bool(b) => {
                if b {
                    fmt::Println!("Bool: true");
                } else {
                    fmt::Println!("Bool: false");
                }
            }
            json::Token::Null => {
                fmt::Println!("Null");
            }
        }
    }
}
