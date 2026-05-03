#![no_std]
#![no_main]

extern crate alloc;

use goish::encoding::json;
use goish::{bytes, nil, slice, string};

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
                goish::fmt::Println!("Delim:", string::__from_vec(alloc::vec::Vec::from(&[d.as_byte()])));
            }
            json::Token::String(s) => {
                goish::fmt::Println!("String:", s);
            }
            json::Token::Number(n) => {
                let s = goish::strconv::FormatFloat(n, 'f' as u8, -1, 64);
                goish::fmt::Println!("Number:", s);
            }
            json::Token::Bool(b) => {
                if b {
                    goish::fmt::Println!("Bool: true");
                } else {
                    goish::fmt::Println!("Bool: false");
                }
            }
            json::Token::Null => {
                goish::fmt::Println!("Null");
            }
        }
    }
}
