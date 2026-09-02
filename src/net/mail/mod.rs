// go: package net/mail
//
// net/mail — RFC 5322 mail message and address parsing.

mod message;

pub use message::{
    Address, AddressParser, ErrHeaderNotPresent, Header, Message, ParseAddress, ParseAddressList,
    ParseDate, ReadMessage,
};
