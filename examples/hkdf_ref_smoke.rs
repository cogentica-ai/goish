// hkdf_ref_smoke — crypto/hkdf against a running Go.
// (crypto/hkdf/hkdf.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_kdf_ref.go` run in
// `package hkdf_test` by `scripts/goref.sh`. goish matched Go on all
// 272 lines — no defects found.
//
// A KDF has no interesting behaviour except its OUTPUT. Two
// implementations that both "derive a key" and disagree by one byte
// produce systems that cannot talk to each other, and the failure
// surfaces as a decryption error somewhere far away with nothing
// pointing back here. So this is byte-for-byte over three hashes
// crossed with four secrets, three salts and three infos, and the
// awkward inputs are the substance.
//
// The rules that do not follow from "it hashes things":
//
//   * An EMPTY salt is not the same as no salt in principle, but HKDF
//     defines it to be: Extract substitutes HashLen zero bytes. A port
//     that skipped that step derives different keys from the same
//     inputs, and only against a real peer would anyone find out.
//   * Expand's output is capped at 255*HashLen — 8160 bytes for
//     SHA-256 — and one byte past it is an ERROR, not a truncated
//     answer. Both sides of that boundary are pinned.
//   * A zero-length request is ALLOWED and returns nothing, rather
//     than being read as "give me the default".
//   * A PRK shorter than HashLen is accepted, which is worth pinning
//     precisely because it looks like it should not be: Expand's
//     security argument assumes a full-length pseudorandom key, but
//     the function does not enforce it, and a port that added the
//     check would reject inputs Go accepts.
//   * The one-shot Key() equals Extract-then-Expand exactly, on every
//     combination.
//
// The last three cases are RFC 5869's own A.1, A.2 and A.3 vectors, so
// this smoke is anchored to the STANDARD and not merely to Go. If both
// implementations were wrong together, those lines would say so.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto::hkdf;
use goish::crypto::sha1;
use goish::crypto::sha256;
use goish::crypto::sha512;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::hash::HashFunc;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 272] = [
    "extract sha256 empty  none  -> prk=b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    "expand  sha256 empty  none  none  -> out=eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe18",
    "key     sha256 empty  none  none  -> same=true err=<nil>",
    "expand  sha256 empty  none  label -> out=cddab1929bc85136374d889e3537ae62ef3cd38286c179fd2a5a6bcb2e06df2f",
    "key     sha256 empty  none  label -> same=true err=<nil>",
    "expand  sha256 empty  none  binary -> out=3d505c952cd058a35b664fdd7a01f831ae7fdb393e0000a2e8c06038e7445195",
    "key     sha256 empty  none  binary -> same=true err=<nil>",
    "extract sha256 empty  short -> prk=379d7f7966f400cb6e3c0b2cca4bf8a2db03b8c81fef8020015b5a3103c30460",
    "expand  sha256 empty  short none  -> out=3575f53d43a910da7c16d7ec27dce663b83bb193d183b5eb3c3bdab69e35efed",
    "key     sha256 empty  short none  -> same=true err=<nil>",
    "expand  sha256 empty  short label -> out=01c6cff20252c19e2075e25481ee04ad4becf3d467d9dc65f298ca82c8249ee3",
    "key     sha256 empty  short label -> same=true err=<nil>",
    "expand  sha256 empty  short binary -> out=359cac2d4b3f9aed55f837d85fbdab9e5f942976bd06865b97efb5d5dd9dd3a6",
    "key     sha256 empty  short binary -> same=true err=<nil>",
    "extract sha256 empty  long  -> prk=71438446517e1acb3f824d0289300efb085064d1ae89150de1169ff87e9c42d5",
    "expand  sha256 empty  long  none  -> out=6f9f623df042ea7315c5da06bb71833fb606063f7681ae3ed457741e626ebe0b",
    "key     sha256 empty  long  none  -> same=true err=<nil>",
    "expand  sha256 empty  long  label -> out=4395e48e4ccf71822a59dad4a9afc05ef107999434293ffa13a5bb53383a9245",
    "key     sha256 empty  long  label -> same=true err=<nil>",
    "expand  sha256 empty  long  binary -> out=0484c2c8f8fb5a4e763b9846b06c711ecd20f3ea74b5bb10928c85a978ed2e10",
    "key     sha256 empty  long  binary -> same=true err=<nil>",
    "extract sha256 short  none  -> prk=1810e8d341b9e61e88895fba0b1aa2bd03cb6c8fff2b368e666ef8efdef5b4fb",
    "expand  sha256 short  none  none  -> out=2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf",
    "key     sha256 short  none  none  -> same=true err=<nil>",
    "expand  sha256 short  none  label -> out=288df20e9258e5c2504360811a765b898de9729e8220131c2f8c2ad72293d4c2",
    "key     sha256 short  none  label -> same=true err=<nil>",
    "expand  sha256 short  none  binary -> out=fc027900dd9c7e4d19c5ab6c10cf31bb6d7c5995228d14106684bd2ce9a3b81e",
    "key     sha256 short  none  binary -> same=true err=<nil>",
    "extract sha256 short  short -> prk=98e5340f0f4f96d2b80c2a90da0d03cf46c35e9492918cc7af73d9a39efa5981",
    "expand  sha256 short  short none  -> out=f1156507c39b0e326159e778696253122de430899a8df2484040a85a5f95ceb1",
    "key     sha256 short  short none  -> same=true err=<nil>",
    "expand  sha256 short  short label -> out=2517052f5634b51a4fed195894d02e388afbf347ea6e676bb74d9a42158dfae9",
    "key     sha256 short  short label -> same=true err=<nil>",
    "expand  sha256 short  short binary -> out=df7612bd3cd27082d1aec9d311b83f39f49d42bb07275995c3c394db14d7baea",
    "key     sha256 short  short binary -> same=true err=<nil>",
    "extract sha256 short  long  -> prk=535858121f666058e147c6cfd95ed7d0653194ab9f3acb07812e44b134a33c57",
    "expand  sha256 short  long  none  -> out=46dc97ab97b37e08e3971a936eea65717d77d286bcfe6ded2a0562fe623d53cc",
    "key     sha256 short  long  none  -> same=true err=<nil>",
    "expand  sha256 short  long  label -> out=eaec1c56c9eff8acab9ff2897430f0a4ac3c8bb916e5977f24bd37276100b91a",
    "key     sha256 short  long  label -> same=true err=<nil>",
    "expand  sha256 short  long  binary -> out=2011a414b0151c239c359e624062e4082a8388c1f7fccd55c90c5d2b7d903965",
    "key     sha256 short  long  binary -> same=true err=<nil>",
    "extract sha256 long   none  -> prk=0fbd7fa39cb0fdc54cc0ed96bd05f56f22481b53d0c648c6b2bbafe7248dfdc1",
    "expand  sha256 long   none  none  -> out=b4f8542cbdd4fa765e94820305f79e5b9d71e4853fd579cef4fa2d44890ac983",
    "key     sha256 long   none  none  -> same=true err=<nil>",
    "expand  sha256 long   none  label -> out=d187bdd6abbf900ef951f34bd45422c6d12cb3b4cfdc3887e9657e4bb3428b2f",
    "key     sha256 long   none  label -> same=true err=<nil>",
    "expand  sha256 long   none  binary -> out=236638b4541c553dfd10f7edc383c1cc08f8d0ec8ca21c115d943d1e03062746",
    "key     sha256 long   none  binary -> same=true err=<nil>",
    "extract sha256 long   short -> prk=834bc1f6bd21a53d4cadeafac9837987727613532a0678b8dcf677e81b10acca",
    "expand  sha256 long   short none  -> out=645f82a2122dac6be3780918cd3cb0dd89b3394515621927bdfc29f493530e6d",
    "key     sha256 long   short none  -> same=true err=<nil>",
    "expand  sha256 long   short label -> out=c0d455dcbf421254f2a4e4167f84663ebd78b7aec585afa2c7828761b5ee4f9c",
    "key     sha256 long   short label -> same=true err=<nil>",
    "expand  sha256 long   short binary -> out=dfadd2bf5269e37e9f16953df42c280656585a04c8a7b80b286249dc8f658bfd",
    "key     sha256 long   short binary -> same=true err=<nil>",
    "extract sha256 long   long  -> prk=171cd9b16957066ed8c2d02711fbc62a4f8f2be6a7cc9a52a2ae23b8f8899bb1",
    "expand  sha256 long   long  none  -> out=3f9d2b1387074ea1f5e58fc4afb463886457855b34c73b0b3765e3e8c1bf46cd",
    "key     sha256 long   long  none  -> same=true err=<nil>",
    "expand  sha256 long   long  label -> out=afc12509b4d055568b9427e73d7d55c666396eeec0f78b11e613a8caa52913d7",
    "key     sha256 long   long  label -> same=true err=<nil>",
    "expand  sha256 long   long  binary -> out=5e23953861673bbb548b146e46a74902f73ec18175f35d24f5d8feecaea24f65",
    "key     sha256 long   long  binary -> same=true err=<nil>",
    "extract sha256 binary none  -> prk=868007c62d64510edfd640abfa2252b8a9072630524ac598d7f84efe02debba3",
    "expand  sha256 binary none  none  -> out=e185ff2dd5c87c47d82f964dcc16bb7d0e5c64909b0b38ca708c8be3e29102af",
    "key     sha256 binary none  none  -> same=true err=<nil>",
    "expand  sha256 binary none  label -> out=cf97554b30d598f076608b773ed3fe3f310d2d7ca3fdff15e88afddbefb6989b",
    "key     sha256 binary none  label -> same=true err=<nil>",
    "expand  sha256 binary none  binary -> out=5551ea054a8ac6b0fa63b154da283ef363f7d96dfa075e04b4ae79e28d133a08",
    "key     sha256 binary none  binary -> same=true err=<nil>",
    "extract sha256 binary short -> prk=bbf88db8c16b67607a8876eb2dda019d1697bd5e4b3c664ec620ec3b5a6c9cb6",
    "expand  sha256 binary short none  -> out=557963e9c9b18a2e66c1dcb8c7d50eb5dd16bc9c5caa95df9b8f70d7f2bd8654",
    "key     sha256 binary short none  -> same=true err=<nil>",
    "expand  sha256 binary short label -> out=88381d3ae01762c0b3293fc2cf167ed5f547edd30c9af50e77125ad8301ceddd",
    "key     sha256 binary short label -> same=true err=<nil>",
    "expand  sha256 binary short binary -> out=3969b879a68f211c6bcf058f7de7e032c4b52886b9fb9f3b73aaf6373ecd0ceb",
    "key     sha256 binary short binary -> same=true err=<nil>",
    "extract sha256 binary long  -> prk=929f958af822f3ed76b14a1e0729da9921d5bbd3da451642dc735c0bc861e89c",
    "expand  sha256 binary long  none  -> out=5242942bd36ce7b7514383cf0068856a6885d39029221f62d6300632cad575f6",
    "key     sha256 binary long  none  -> same=true err=<nil>",
    "expand  sha256 binary long  label -> out=c4b6f769c690c94349cb00b03807c3d8a0df8d847011fc84cd04b1df861cedf2",
    "key     sha256 binary long  label -> same=true err=<nil>",
    "expand  sha256 binary long  binary -> out=8a3925fed0de5738dd42a40619a873cb5fe4b2b3a2269d7155da17edce2cab17",
    "key     sha256 binary long  binary -> same=true err=<nil>",
    "extract sha512 empty  none  -> prk=b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
    "expand  sha512 empty  none  none  -> out=9d73c98e791e80ebe5b4cb45693aa32fdd44b5fa3edab3ec82f9d0f4d66905e2215ad0d4ac20fe570da59a5d189fdde60e55f283703cd19bc95ebb16fc1c868e",
    "key     sha512 empty  none  none  -> same=true err=<nil>",
    "expand  sha512 empty  none  label -> out=c9c4beb661933faeec0d68245be96a19c5d9254be6ffc15eb6e0ab5834cf742190171a987c7ccf355a1cc570cc1586c6f767dafe014f2ceab8ac2bcb94ecef90",
    "key     sha512 empty  none  label -> same=true err=<nil>",
    "expand  sha512 empty  none  binary -> out=c130d155fa6a12b2661da18726a2e7ccd3ef2ed1a713020d914dabb2ecf7bf31bc8f10b8ad6dec805caefe387a946c2742e3727cb28d459b953f55acdf01b59a",
    "key     sha512 empty  none  binary -> same=true err=<nil>",
    "extract sha512 empty  short -> prk=ed2fbac156e7a55a01218c6b17e243cbd5ac6368cc0730d055d059a8c68557453652116cd5ee10936760a3cafa07124dd238c1eeeec5cf0574623e2c120e0234",
    "expand  sha512 empty  short none  -> out=28a09a1b02acd508b3d5f4ac9cbf945ef32f79b1f318672922f8a2e50bcd26abfa4551e38bed7628be78eae6664c97cb5dcc602872caada950cadbb8ef67faa7",
    "key     sha512 empty  short none  -> same=true err=<nil>",
    "expand  sha512 empty  short label -> out=ec1fa6fdeb884699f819dd3fbf55c4a5add3c21fef847af71fb62495d2a381d9075f12514844b1a0a8e14a579f8d115fed9e438fd83fbbc54dc427c97d9e867a",
    "key     sha512 empty  short label -> same=true err=<nil>",
    "expand  sha512 empty  short binary -> out=15dfa5017b6edbc086c71ec96733821337171c148cf5a0dd6872c45dc3298e2585e58b9422962ed458f48ad3426896ba36966af06f8d718c0c1c7851625ff961",
    "key     sha512 empty  short binary -> same=true err=<nil>",
    "extract sha512 empty  long  -> prk=bbf9436a495ef50510726dd791f274df3a627a3a8c41cbfc8e22ccced9ec93c63ebc5c1d17f6cc0e0e387b76c91cee525bf8c414eb33da63fb523bc3fa735542",
    "expand  sha512 empty  long  none  -> out=a8305eaecb869efb5340a3b49087dcfb703a0446df641408f39de93a2c19cbf1e9f6b91e06405f09fc00ab09ada76303a13648dfe612911f3c2fa3cdc1663ea3",
    "key     sha512 empty  long  none  -> same=true err=<nil>",
    "expand  sha512 empty  long  label -> out=c0f0d4cf242e79d5687dbfc54338b5fdf0b976165912ecb7d5ff50a4f512350f661576fb968987fb4784a6cc66441fba3c4e86329ce9279ac63ff0711b65acdf",
    "key     sha512 empty  long  label -> same=true err=<nil>",
    "expand  sha512 empty  long  binary -> out=7620ea444d1cd0edfac4a163fe8f86a56a7671a61204bef9ae304304709b7a11644dbe787edd11b76e56de0ca71002cd0c031a541c64efc137e152b2724cae46",
    "key     sha512 empty  long  binary -> same=true err=<nil>",
    "extract sha512 short  none  -> prk=88973d978cf503fce34edb7d5f79eb982d0ef978cc5ee4c808cf678672ad7fea2684f92f114ffaa03482f7ec1b2bd3489e647d6fa72145de44aaadc91515a821",
    "expand  sha512 short  none  none  -> out=ce251b8403130b6b2b54721a86eb1af50f221c4e326bc36db714eaf0224767ca55b4d73f21367c99b56597a48f52f076ee9cd993c4dd237d75263fb85dfbdb28",
    "key     sha512 short  none  none  -> same=true err=<nil>",
    "expand  sha512 short  none  label -> out=9167efb9c512bcd34cfa304bdc3769c23293f278346f34ae378d9a52666b566a84ea197288a05ddac3c6efd2422552e676e22de10794bab6d1e59bcea663db8a",
    "key     sha512 short  none  label -> same=true err=<nil>",
    "expand  sha512 short  none  binary -> out=15f63819cab3d56bdd540d3ef146049153dbcb5a860a47d49a4eb0bee2e79911bb534d0ef5a61758189f19aed09fe13ebc031da2ccb2dcb1d3a00561af40539b",
    "key     sha512 short  none  binary -> same=true err=<nil>",
    "extract sha512 short  short -> prk=57e6f1ea12666f2277f8ac044f50ff7eab5e7f3557dbdbca0a21e21a0afa1bd6260cc09686e369fbee8d2da27296d7c2e4864b75accc2c7477cbecf3a38c9be7",
    "expand  sha512 short  short none  -> out=683045181e6325bbd2a5ba7fc5cecc3bf0d9bfe0963c3943867cf19c2b5de335faf87a0ad2a75688c78f63dc812a3c5d3ce29ed20ddadaf0edfb985789c66c90",
    "key     sha512 short  short none  -> same=true err=<nil>",
    "expand  sha512 short  short label -> out=2a20c1831f43e5fc7b9ff7e371dd836c14c0e07b7e03638530d0c969f4be2d15dcfe8114c1b0e5c0cf6e1e8cad28fca51d677b1c1747c37d7aebf76612872177",
    "key     sha512 short  short label -> same=true err=<nil>",
    "expand  sha512 short  short binary -> out=cebe994afe247fe3b5b6c975699fd49cdae8141e71e7135ac083634dc5cc6544ba498bdcd091043d3215b60c9d006feb7eb2e240bc06e54dc24a0f7a7b1f150e",
    "key     sha512 short  short binary -> same=true err=<nil>",
    "extract sha512 short  long  -> prk=a2000ed0e955a1835e70273ec44b034d30937920598cbd0f2d0a82c5630b1a45e6e1d1bfc5a84736b14ab2a602b17dd948b8af80bb81a56bdf17817670ae3dc2",
    "expand  sha512 short  long  none  -> out=1fcead4d5c6850b881709f28bb8ff5c415256cbe2395eebe457112908146b45891a81a5e4ca3d38a163336f614db883713d7f3e7f3e7887bca1d43b3315ac974",
    "key     sha512 short  long  none  -> same=true err=<nil>",
    "expand  sha512 short  long  label -> out=d8ae43a5260b1d9e714b3541cfa2ecd0620f58232bbaedf6d943f4449dd4e5a735311324ccf1f7760f961cc18bdd35cbfde38669bf54d9a126d6b81eafb5e288",
    "key     sha512 short  long  label -> same=true err=<nil>",
    "expand  sha512 short  long  binary -> out=02473884391c7a78a2fa63268ae4d6dca91d0429909ac85b4a94c10d76bfcff5402b35917828e2344f8ffeb60ea3a2c9959f990f0f7a8bec447b425f3510ed26",
    "key     sha512 short  long  binary -> same=true err=<nil>",
    "extract sha512 long   none  -> prk=e7e7dab764afd3c98d218d9396bb49f28fae739fc99e1711ef7259f55520b578feca34a4f2c9e2f68079d4caaeb9230833a5d7e5637b343d24996187e13b9be4",
    "expand  sha512 long   none  none  -> out=f8b3c09607933097c9525f66717b7c90b115e34342cd63ebe2c0ff9a3f3170ceca334cc2ac2b57507198887c2942273b7a6252a1ca0dd523647c46ab703b99b9",
    "key     sha512 long   none  none  -> same=true err=<nil>",
    "expand  sha512 long   none  label -> out=8662af6e53896b5f0d09d94b9bfdeb858fe04306a8a3b5659f9a72a19412eb6ce38bb2d71eaa1f52002b3827263bb3e8b9fdfec4b0933864d13044a4840ecf33",
    "key     sha512 long   none  label -> same=true err=<nil>",
    "expand  sha512 long   none  binary -> out=9f4de613d4b1359abe8e98a932b3e2df650cfd157c83dc848fd79a29cf472c0d3a78bd82b438a4c76fddf7c1a0fb0bc57f2da7a57d99839e6d21090618a9bc20",
    "key     sha512 long   none  binary -> same=true err=<nil>",
    "extract sha512 long   short -> prk=40fb78041211c70b21ff969544a28971b99e0edb1617452f7144ac968a7357283da0eaa0e80ecc1bbaafc65252f947cc6ea97bfbb21b01de3915dda3307f023a",
    "expand  sha512 long   short none  -> out=c49fb35b2ca8359e945dcc530f464aa5931066b97f98e807b00d1f4f8780dddf3fb83ffca2a8886d115b9887cb03148a66f100ce82ca45569ea703e9cd8942f8",
    "key     sha512 long   short none  -> same=true err=<nil>",
    "expand  sha512 long   short label -> out=560d8f007c31716ea1f2c1f4262b2e7d2875dd995c33d4e98aae6b695fe581c5c2abb96ae19e425bc85883387f86e3078306b39ef908a8cc191580a72056c2b0",
    "key     sha512 long   short label -> same=true err=<nil>",
    "expand  sha512 long   short binary -> out=9fa7ff5aa4777f1648bda332563830475ddbcc17040224a3bb16c929e0a257fc37fbf0de54b39c24e3ec63b817eb6bc8e6177b6e0b66b7137c8c46390f3af443",
    "key     sha512 long   short binary -> same=true err=<nil>",
    "extract sha512 long   long  -> prk=e787d7a543b79fc9043b1fea5ac552a2598a037d4e46848fcb8ecbaa3359c96273bd8cdf874653721a9d1cabded6ccf4f56647e12fbef86b602283bbf18e1ca2",
    "expand  sha512 long   long  none  -> out=9e4032950e6c91f81fa60ccfdf0d392ebac27dbae4d1e75ac7745da757c6f6cba862994572ee9e2c10cdd1814b434df99293de1a04df2506008767689db15a49",
    "key     sha512 long   long  none  -> same=true err=<nil>",
    "expand  sha512 long   long  label -> out=8e026b92ab2540932748f79c134b5652796591b3fc0d9ecd48880a0c5ce2847e56ea630974276c9116336da4944cffae99efae5a0ce2ce88bcad6e43e03c82a5",
    "key     sha512 long   long  label -> same=true err=<nil>",
    "expand  sha512 long   long  binary -> out=c11445ee94667d96c707b8298bb0a405c613b3caaf4a864dec459fd14f6f827ef8dcf522bf327dbe3342113465fc0387181dd4eca39574ed3637eff08cbca679",
    "key     sha512 long   long  binary -> same=true err=<nil>",
    "extract sha512 binary none  -> prk=0c44617e34919454826dc48d2493791edb04e02bc46b30f3c41e0f5cf0c6e04f3affe1cdff28771aa61d87c3503cc1f44c3f919f9ece09ac0aa855cf8d27dc10",
    "expand  sha512 binary none  none  -> out=374d799f6cd43027a9ec4a17b817f3109e090f0f6d1bef5db2eb58c2c80f6ac39daf161826643636c534013a9f7e53243a12f193423deb93b4f68009f2b6a95f",
    "key     sha512 binary none  none  -> same=true err=<nil>",
    "expand  sha512 binary none  label -> out=bcdbeeed2266cb809c3aaccd7fcf8801416161180bbb09426944e4b3ee757428c499e598d518713a6cc91118f4f13112d20cd2174e14a361bbadd8da0e94521b",
    "key     sha512 binary none  label -> same=true err=<nil>",
    "expand  sha512 binary none  binary -> out=30ed03379f8abb5330566e1a4d6956bf761533495e0c428b8d3d7fb645b04e3313a9c55e112152febe15b81053e68537a276ee3b4f6e996fdfcd1936ccce63ee",
    "key     sha512 binary none  binary -> same=true err=<nil>",
    "extract sha512 binary short -> prk=9340ef685c4e9cb56b3b15a6c81614c772c4e82ed5c0e6d6fb7b5f49bf8b5a346fc4f86444d10d75155ab454cf52547a42676ec47e8d8e1fee18924a30a21b47",
    "expand  sha512 binary short none  -> out=a9c4341cd2ce46c295dffe96eeea4d65c40051057a6b5edc8110a447aa77f90fee169194c071f2364fc1216cdd49879cf99c8219eca29e157e95ed18e42a2008",
    "key     sha512 binary short none  -> same=true err=<nil>",
    "expand  sha512 binary short label -> out=b01ff7e04a121daaeda1dea6fa50f633c5443eca23a1b3bd947b1cf218eaaf3f4ef6575e47a330eefb537d10922d6ce8f1fc144fb4b0930ede037174701e8b1a",
    "key     sha512 binary short label -> same=true err=<nil>",
    "expand  sha512 binary short binary -> out=74104b08283669f0819350edaefedeefd6fad3d1d8f4ff8b931b7990b870a0bf458e7877a6ab2a74b7dfb44c792a7f5bc1d2602fdf6d9f9a0e7a862c49642f5f",
    "key     sha512 binary short binary -> same=true err=<nil>",
    "extract sha512 binary long  -> prk=addc2c7bc792f83b79154e5c2b36849e94bbead7a37d9748f69d3f40042268633ed106f10b75a93568b660634354ee84be6184aeac5be6693ef4c098beeb939a",
    "expand  sha512 binary long  none  -> out=afbb2b3ae9b3d8e35464e514be52d26265244a91bec06ddaa8c6a69c73e5e65ee77dcbe2cdefb653749a608ff3f3d2e57ed0d8b79b90fb4999294851bb5eed5a",
    "key     sha512 binary long  none  -> same=true err=<nil>",
    "expand  sha512 binary long  label -> out=33bd7225ca63cd1e19843171abf0317c6af4581f62d181932046d1972979ba0308ef11bcf6646f057b99354a779a3d3403f1ff73d1cbe137e91061d6983aa124",
    "key     sha512 binary long  label -> same=true err=<nil>",
    "expand  sha512 binary long  binary -> out=d8a7ca1b856ca2b71f1069b09cb30198e97c2461d31c3a3ef57cf1e684b1a802bb89567c1421af940182ac3d81a037071fcce76ba907d8e73545fc5724df4f11",
    "key     sha512 binary long  binary -> same=true err=<nil>",
    "extract sha1   empty  none  -> prk=fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
    "expand  sha1   empty  none  none  -> out=885fc029b3224b896e09e0bbe5eb347ec59e6827",
    "key     sha1   empty  none  none  -> same=true err=<nil>",
    "expand  sha1   empty  none  label -> out=73d4585d02318e4978409ee004d36a7d31d835d2",
    "key     sha1   empty  none  label -> same=true err=<nil>",
    "expand  sha1   empty  none  binary -> out=a54216cdde93c25b55435c843cf7230188e40403",
    "key     sha1   empty  none  binary -> same=true err=<nil>",
    "extract sha1   empty  short -> prk=2c8e8c6044d03932ecb46600946ccb9e17f63ba4",
    "expand  sha1   empty  short none  -> out=19f9cb1ef636eb511d820c6ef588c8430acf904b",
    "key     sha1   empty  short none  -> same=true err=<nil>",
    "expand  sha1   empty  short label -> out=0cfda1bc4731bfe759c162db001b4e432bd07576",
    "key     sha1   empty  short label -> same=true err=<nil>",
    "expand  sha1   empty  short binary -> out=3833a91660be91f299df5f95f0f2068e926e9ada",
    "key     sha1   empty  short binary -> same=true err=<nil>",
    "extract sha1   empty  long  -> prk=b86eff296ecbfbae91567012dd2436406cc3bcdf",
    "expand  sha1   empty  long  none  -> out=20ea624e0f995ad1c2e4c0b836afbbd5aa90efd0",
    "key     sha1   empty  long  none  -> same=true err=<nil>",
    "expand  sha1   empty  long  label -> out=bcc3a51ec8652510ce9574a1162cbf51ae9383d0",
    "key     sha1   empty  long  label -> same=true err=<nil>",
    "expand  sha1   empty  long  binary -> out=93579dfebca5629efdac362e834784bb55dc4397",
    "key     sha1   empty  long  binary -> same=true err=<nil>",
    "extract sha1   short  none  -> prk=4a52a1ea24919e7655f76cce01b2ddb97a9e2918",
    "expand  sha1   short  none  none  -> out=7241733aa88c791e52976d56e33a5cccc35acda2",
    "key     sha1   short  none  none  -> same=true err=<nil>",
    "expand  sha1   short  none  label -> out=d1a401c8a89563fe96512adebafedfb0a53f953c",
    "key     sha1   short  none  label -> same=true err=<nil>",
    "expand  sha1   short  none  binary -> out=c65fd424b7a39bb0e46963a571f0516f03958fbb",
    "key     sha1   short  none  binary -> same=true err=<nil>",
    "extract sha1   short  short -> prk=5bfb52c459cdb07218c176b5ddec9b6215bd5b76",
    "expand  sha1   short  short none  -> out=e784c3729cd404c92940d8559c45bcf67384ee07",
    "key     sha1   short  short none  -> same=true err=<nil>",
    "expand  sha1   short  short label -> out=8376d7eb736eefff7aa90bbf3078584097c9db0c",
    "key     sha1   short  short label -> same=true err=<nil>",
    "expand  sha1   short  short binary -> out=c9a091c295abc6b8bd55e308f9dec57470bfeb4a",
    "key     sha1   short  short binary -> same=true err=<nil>",
    "extract sha1   short  long  -> prk=78b46a140da88580c10f276c2f5e028460285818",
    "expand  sha1   short  long  none  -> out=ec2f7bcb02afed1cd8962f37c1d7f5de26674c0a",
    "key     sha1   short  long  none  -> same=true err=<nil>",
    "expand  sha1   short  long  label -> out=1a66dc84242ffc7cd2bd0358ad6eee72bb13e6e4",
    "key     sha1   short  long  label -> same=true err=<nil>",
    "expand  sha1   short  long  binary -> out=e7cdcd53babdd78caf77b1950c69ccfdf8bb579c",
    "key     sha1   short  long  binary -> same=true err=<nil>",
    "extract sha1   long   none  -> prk=64c0335792e800eafd44b6f81800898d2504106b",
    "expand  sha1   long   none  none  -> out=ea7eab5789e8e6677693f1f7e34e681d531a637f",
    "key     sha1   long   none  none  -> same=true err=<nil>",
    "expand  sha1   long   none  label -> out=6e3aa8402d4725e6a04c95bd44cd933d2f549751",
    "key     sha1   long   none  label -> same=true err=<nil>",
    "expand  sha1   long   none  binary -> out=41daa25dc78fe75c7655656cc3c3c18be4b8f720",
    "key     sha1   long   none  binary -> same=true err=<nil>",
    "extract sha1   long   short -> prk=7cfbdf5e58166995d63d95b609789955061cc796",
    "expand  sha1   long   short none  -> out=109f37616199d872cf00f6b21ddd97df077ddf90",
    "key     sha1   long   short none  -> same=true err=<nil>",
    "expand  sha1   long   short label -> out=27f19bc6f7b7531e92881d64a4a25f8f1a3179b3",
    "key     sha1   long   short label -> same=true err=<nil>",
    "expand  sha1   long   short binary -> out=fc9280060a877b165a827e623085f144945f2ae6",
    "key     sha1   long   short binary -> same=true err=<nil>",
    "extract sha1   long   long  -> prk=fb83934a22f4376a2d8a442352b0f2e7b3d5f2ff",
    "expand  sha1   long   long  none  -> out=09f017d3316ade7b23dd1fa1efa096e29cfe9e83",
    "key     sha1   long   long  none  -> same=true err=<nil>",
    "expand  sha1   long   long  label -> out=e1eecac7678860079063d31eb794af8f7ed5a036",
    "key     sha1   long   long  label -> same=true err=<nil>",
    "expand  sha1   long   long  binary -> out=bfdfc4097adb3651e261f8019c4d332ed9de2c28",
    "key     sha1   long   long  binary -> same=true err=<nil>",
    "extract sha1   binary none  -> prk=80fdc339d435d00b6c8ceb0515d6eb23fa2c849c",
    "expand  sha1   binary none  none  -> out=7b6772412b1cfb9ee1984e4b503115b45cf1a142",
    "key     sha1   binary none  none  -> same=true err=<nil>",
    "expand  sha1   binary none  label -> out=abc234de7f5078df8fa34ab6e57f09cb2fccfe98",
    "key     sha1   binary none  label -> same=true err=<nil>",
    "expand  sha1   binary none  binary -> out=657c374c300bc48dcbc165791cfe16c8e1da3b8e",
    "key     sha1   binary none  binary -> same=true err=<nil>",
    "extract sha1   binary short -> prk=f518f03d6dd02178057cf11e777e252b79ba1f98",
    "expand  sha1   binary short none  -> out=4114a0702418525dd2fae5ef97111519a48b7695",
    "key     sha1   binary short none  -> same=true err=<nil>",
    "expand  sha1   binary short label -> out=4e8c1d18fde69dedc2142fb7b95bba602ea00df3",
    "key     sha1   binary short label -> same=true err=<nil>",
    "expand  sha1   binary short binary -> out=fdfd32d5e9201ccec0eeb6771e6ed2c36459abe3",
    "key     sha1   binary short binary -> same=true err=<nil>",
    "extract sha1   binary long  -> prk=2801d62fd0c41a97f79276c2aeeeef758e8328c1",
    "expand  sha1   binary long  none  -> out=3cf7d8890fb5b5edf682bca2ab716f4dc79c6a40",
    "key     sha1   binary long  none  -> same=true err=<nil>",
    "expand  sha1   binary long  label -> out=825dbfa32bad8149b6ccc70d938548f986dc53a1",
    "key     sha1   binary long  label -> same=true err=<nil>",
    "expand  sha1   binary long  binary -> out=9a66f6583b49cca49b062926c5381198425c1c87",
    "key     sha1   binary long  binary -> same=true err=<nil>",
    "len 0        -> n=0      out=",
    "len 1        -> n=1      out=f6",
    "len 31       -> n=31     out=f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776",
    "len 32       -> n=32     out=f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef",
    "len 33       -> n=33     out=f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef…",
    "len 64       -> n=64     out=f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef…",
    "len 8160     -> n=8160   out=f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef…",
    "len 8161     -> err=\"hkdf: requested key length too large\"",
    "prklen 0    -> out=d3dbc270ada4bfd42baf1210c7487eac8e021d5d9104b1aba3373d9fc6304421",
    "prklen 1    -> out=9e77aa05f15b105275b63d1e05f86723f0f177584fa9f769b2e09e9e5e1772ff",
    "prklen 31   -> out=41cf23e37fcd54633d6a1fcac80da601f54116c2feef991efdbe29923986d144",
    "prklen 32   -> out=8d991b271ac69900da557d3a74d20d2b75d5ffaa61264b893ad129806651c9e4",
    "prklen 33   -> out=685dfb27f4afc476dd6792a435ab636420f938edf9e63ed8c09b037312d3f9a0",
    "prklen 64   -> out=80a5331f28bda31d90138b4791abcec781a96d2b147dd603cfae6ad04cacd53f",
    "rfc-a1 prk=077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    "rfc-a1 okm=3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865 err=<nil>",
    "rfc-a2 prk=06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    "rfc-a2 okm=b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87 err=<nil>",
    "rfc-a3 prk=19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    "rfc-a3 okm=8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8 err=<nil>",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn sb(x: &string) -> slice<byte> {
    return bs(x.as_bytes().to_vec());
}
fn hx(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.to_vec());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let hashes: [(&str, HashFunc, int); 3] = [
        ("sha256", HashFunc::New(sha256::NewHash), 32),
        ("sha512", HashFunc::New(sha512::NewHash), 64),
        ("sha1", HashFunc::New(sha1::NewHash), 20),
    ];
    let secrets: [(&str, string); 4] = [
        ("empty", string::new()),
        ("short", s("secret")),
        ("long", strings::Repeat(s("k"), 200)),
        ("binary", string::from_bytes(b"\x00\x01\xfe\xff")),
    ];
    let salts: [(&str, string); 3] = [
        ("none", string::new()),
        ("short", s("salt")),
        ("long", strings::Repeat(s("s"), 100)),
    ];
    let infos: [(&str, string); 3] = [
        ("none", string::new()),
        ("label", s("goish reference")),
        ("binary", string::from_bytes(b"\x00\xff")),
    ];
    for (hn, hf, size) in hashes.iter() {
        for (sn, sv) in secrets.iter() {
            for (saln, salv) in salts.iter() {
                let (prk, e) = hkdf::Extract(hf.clone(), sb(sv), sb(salv));
                if e != goish::nil {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!(
                            "extract %-6s %-6s %-5s -> err=%q",
                            s(hn),
                            s(sn),
                            s(saln),
                            e.Error()
                        ),
                    );
                    continue;
                }
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "extract %-6s %-6s %-5s -> prk=%s",
                        s(hn),
                        s(sn),
                        s(saln),
                        hx(&prk)
                    ),
                );
                for (infn, infv) in infos.iter() {
                    let (out, e) = hkdf::Expand(hf.clone(), prk.clone(), infv.clone(), *size);
                    if e != goish::nil {
                        chk(
                            &mut failed,
                            &mut ln,
                            fmt::Sprintf!(
                                "expand  %-6s %-6s %-5s %-5s -> err=%q",
                                s(hn),
                                s(sn),
                                s(saln),
                                s(infn),
                                e.Error()
                            ),
                        );
                        continue;
                    }
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!(
                            "expand  %-6s %-6s %-5s %-5s -> out=%s",
                            s(hn),
                            s(sn),
                            s(saln),
                            s(infn),
                            hx(&out)
                        ),
                    );
                    let (k, kerr) = hkdf::Key(hf.clone(), sb(sv), sb(salv), infv.clone(), *size);
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!(
                            "key     %-6s %-6s %-5s %-5s -> same=%v err=%s",
                            s(hn),
                            s(sn),
                            s(saln),
                            s(infn),
                            hx(&k) == hx(&out),
                            errText(kerr)
                        ),
                    );
                }
            }
        }
    }
    {
        let (prk, _) = hkdf::Extract(
            HashFunc::New(sha256::NewHash),
            sb(&s("secret")),
            sb(&s("salt")),
        );
        for n in [0i64, 1, 31, 32, 33, 64, 255 * 32, 255 * 32 + 1] {
            let (out, e) = hkdf::Expand(HashFunc::New(sha256::NewHash), prk.clone(), s("info"), n);
            if e != goish::nil {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("len %-8d -> err=%q", n, e.Error()),
                );
                continue;
            }
            let full = hx(&out);
            let shown = if full.Len() > 64 {
                string::from_bytes(&full.as_bytes()[..64]) + "…"
            } else {
                full
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("len %-8d -> n=%-6d out=%s", n, out.Len(), shown),
            );
        }
    }
    {
        for n in [0usize, 1, 31, 32, 33, 64] {
            let prk = bs(alloc::vec![b'p'; n]);
            let (out, e) = hkdf::Expand(HashFunc::New(sha256::NewHash), prk, s("info"), 32);
            if e != goish::nil {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("prklen %-4d -> err=%q", n as int, e.Error()),
                );
                continue;
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("prklen %-4d -> out=%s", n as int, hx(&out)),
            );
        }
    }
    {
        let vecs: [(&str, &str, &str, &str, int); 3] = [
            ("rfc-a1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42),
            ("rfc-a2",
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
             "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
             "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
             82),
            ("rfc-a3", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42),
        ];
        for (name, ikmh, salth, infoh, n) in vecs.iter() {
            let (ikm, _) = hex::DecodeString(ikmh);
            let (salt, _) = hex::DecodeString(salth);
            let (info, _) = hex::DecodeString(infoh);
            let (prk, _) = hkdf::Extract(HashFunc::New(sha256::NewHash), ikm, salt);
            let infoStr = string::from_bytes(&info.to_vec());
            let (okm, e) = hkdf::Expand(HashFunc::New(sha256::NewHash), prk.clone(), infoStr, *n);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%s prk=%s", s(name), hx(&prk)),
            );
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%s okm=%s err=%s", s(name), hx(&okm), errText(e)),
            );
        }
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
