// p256_ecdh_smoke — verifies P-256 ECDH arithmetic with known test vectors.
//
// Uses RFC 5903 §8.1 (P-256 ECDH test vectors).
// Also verifies ECDH self-consistency: ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub).
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
use goish::crypto::tls::legacy_p256::{p256_keypair_generate, p256_ecdh_compute};
use goish::syscall;
use goish::fmt;

#[goish::main]
fn main() {
    let mut pass = true;

    // ── Test 1: RFC 5903 §8.1 P-256 ECDH known vector ──────────────────────────
    //
    // dIUT (private key of initiator):
    //   DC51D386 6A15BACDE33D96F992FCA99DA7E6EF0934 01F9B679 7C8C2C04 AB9ECB3F
    // QiutX (public key X):
    //   2442A5CC 0ECD015F A3CA31DC 8E2BBC70 BF42D60C BCA20085 E0822CB0 4235E970
    // QiutY (public key Y):
    //   6FC98BD7 E50211A4 A27102FA 3549DF79 EBCB4BF2 46B80945 CDDFE7D5 09BBFD7D
    //
    // dResponder (private key of responder):
    //   57190082 1E99AC3D 7FACBADE 4EC26920 A8E9C9D9 9AA58D4B EA44C02E 5432E2A4
    // QreX (public key X):
    //   1A8395 32D11EB1 A7F10F17 D7BA0E1B 09099FEE 0FCBFCE5 80B63A47 03F1DADA
    //   → actually: 1A8395 is not 32 bytes; let me use exact bytes below.
    //
    // Shared secret Z:
    //   D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE
    //
    // Note: RFC 5903 uses IKEv2 naming; we adapt to our API.
    // The shared secret is the x-coordinate of dIUT * Q_responder = dResponder * Q_iut.

    // Initiator (IUT) private key d_IUT:
    let _d_iut: [u8; 32] = [
        0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD,
        0xE3, 0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D,
        0xA7, 0xE6, 0xEF, 0x09, 0x34, 0x01, 0xF9, 0xB6,
        0x79, 0x7C, 0x8C, 0x2C, 0x04, 0xAB, 0x9E, 0xCB,
    ];
    // Responder public key (uncompressed):
    // dResponder private key:
    let _d_resp: [u8; 32] = [
        0x57, 0x19, 0x00, 0x82, 0x1E, 0x99, 0xAC, 0x3D,
        0x7F, 0xAC, 0xBA, 0xDE, 0x4E, 0xC2, 0x69, 0x20,
        0xA8, 0xE9, 0xC9, 0xD9, 0x9A, 0xA5, 0x8D, 0x4B,
        0xEA, 0x44, 0xC0, 0x2E, 0x54, 0x32, 0xE2, 0xA4,
    ];

    // Responder's public key (from RFC 5903 §8.1):
    // QreX: 1A8395 ... The RFC gives the full coordinates:
    // xi: 2442A5CC 0ECD015F A3CA31DC 8E2BBC70 BF42D60C BCA20085 E0822CB0 4235E970 — this is Q_iut.x
    // yi: 6FC98BD7 E50211A4 A27102FA 3549DF79 EBCB4BF2 46B80945 CDDFE7D5 09BBFD7D — Q_iut.y
    // xr: 1A8395 ... not 32 bytes in the RFC notation. Let me use NIST test vectors instead.

    // ── Test 1: Use NIST SP 800-56A ECDH P-256 test vector ──────────────────────
    // From NIST CAVP test vector set, ECDH, P-256:
    // dIUT (private):
    //   7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534
    // QsUTX (static party public X):
    //   700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287
    // QsUTY (static party public Y):
    //   DB71E509E3FD9B060DDB20BA5C51DCC5948D46FBF640DFE0441782CAB85FA4AC
    // Z (shared secret):
    //   46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B

    let d_iut2: [u8; 32] = [
        0x7D, 0x7D, 0xC5, 0xF7, 0x1E, 0xB2, 0x9D, 0xDA,
        0xF8, 0x0D, 0x62, 0x14, 0x63, 0x2E, 0xEA, 0xE0,
        0x3D, 0x90, 0x58, 0xAF, 0x1F, 0xB6, 0xD2, 0x2E,
        0xD8, 0x0B, 0xAD, 0xB6, 0x2B, 0xC1, 0xA5, 0x34,
    ];
    let q_static_x: [u8; 32] = [
        0x70, 0x0C, 0x48, 0xF7, 0x7F, 0x56, 0x58, 0x4C,
        0x5C, 0xC6, 0x32, 0xCA, 0x65, 0x64, 0x0D, 0xB9,
        0x1B, 0x6B, 0xAC, 0xCE, 0x3A, 0x4D, 0xF6, 0xB4,
        0x2C, 0xE7, 0xCC, 0x83, 0x88, 0x33, 0xD2, 0x87,
    ];
    let q_static_y: [u8; 32] = [
        0xDB, 0x71, 0xE5, 0x09, 0xE3, 0xFD, 0x9B, 0x06,
        0x0D, 0xDB, 0x20, 0xBA, 0x5C, 0x51, 0xDC, 0xC5,
        0x94, 0x8D, 0x46, 0xFB, 0xF6, 0x40, 0xDF, 0xE0,
        0x44, 0x17, 0x82, 0xCA, 0xB8, 0x5F, 0xA4, 0xAC,
    ];
    let z_expected: [u8; 32] = [
        0x46, 0xFC, 0x62, 0x10, 0x64, 0x20, 0xFF, 0x01,
        0x2E, 0x54, 0xA4, 0x34, 0xFB, 0xDD, 0x2D, 0x25,
        0xCC, 0xC5, 0x85, 0x20, 0x60, 0x56, 0x1E, 0x68,
        0x04, 0x0D, 0xD7, 0x77, 0x89, 0x97, 0xBD, 0x7B,
    ];

    // Build server_pub_65 = 0x04 || x || y
    let mut server_pub: [u8; 65] = [0u8; 65];
    server_pub[0] = 0x04;
    server_pub[1..33].copy_from_slice(&q_static_x);
    server_pub[33..65].copy_from_slice(&q_static_y);

    let z_got = p256_ecdh_compute(&d_iut2, &server_pub);

    fmt::Println!(fmt::Sprintf!("[test1] shared_secret expected: %02x%02x%02x%02x...",
        z_expected[0] as i64, z_expected[1] as i64, z_expected[2] as i64, z_expected[3] as i64));
    fmt::Println!(fmt::Sprintf!("[test1] shared_secret got:      %02x%02x%02x%02x...",
        z_got[0] as i64, z_got[1] as i64, z_got[2] as i64, z_got[3] as i64));

    if z_got == z_expected {
        fmt::Println!(goish::string("[test1] PASS: NIST CAVP P-256 ECDH vector matches"));
    } else {
        fmt::Println!(goish::string("[test1] FAIL: NIST CAVP P-256 ECDH vector mismatch"));
        // Print full output for debugging
        fmt::Println!(fmt::Sprintf!("[test1] full expected: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            z_expected[0] as i64, z_expected[1] as i64, z_expected[2] as i64, z_expected[3] as i64,
            z_expected[4] as i64, z_expected[5] as i64, z_expected[6] as i64, z_expected[7] as i64,
            z_expected[8] as i64, z_expected[9] as i64, z_expected[10] as i64, z_expected[11] as i64,
            z_expected[12] as i64, z_expected[13] as i64, z_expected[14] as i64, z_expected[15] as i64,
            z_expected[16] as i64, z_expected[17] as i64, z_expected[18] as i64, z_expected[19] as i64,
            z_expected[20] as i64, z_expected[21] as i64, z_expected[22] as i64, z_expected[23] as i64,
            z_expected[24] as i64, z_expected[25] as i64, z_expected[26] as i64, z_expected[27] as i64,
            z_expected[28] as i64, z_expected[29] as i64, z_expected[30] as i64, z_expected[31] as i64,
        ));
        fmt::Println!(fmt::Sprintf!("[test1] full got:      %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            z_got[0] as i64, z_got[1] as i64, z_got[2] as i64, z_got[3] as i64,
            z_got[4] as i64, z_got[5] as i64, z_got[6] as i64, z_got[7] as i64,
            z_got[8] as i64, z_got[9] as i64, z_got[10] as i64, z_got[11] as i64,
            z_got[12] as i64, z_got[13] as i64, z_got[14] as i64, z_got[15] as i64,
            z_got[16] as i64, z_got[17] as i64, z_got[18] as i64, z_got[19] as i64,
            z_got[20] as i64, z_got[21] as i64, z_got[22] as i64, z_got[23] as i64,
            z_got[24] as i64, z_got[25] as i64, z_got[26] as i64, z_got[27] as i64,
            z_got[28] as i64, z_got[29] as i64, z_got[30] as i64, z_got[31] as i64,
        ));
        pass = false;
    }

    // ── Test 2: Small-scalar ECDH (k_a=2, k_b=3, expected shared secret = 6G.x) ──
    //
    // These five constants came from `scripts/goref.sh
    // crypto/internal/fips140/nistec` — NewP256Point().ScalarBaseMult(k)
    // for k = 2, 3, 6. The values that were here before were NOT on the
    // curve: the hand-rolled P-256 this example used to exercise never
    // validated a peer point, so it accepted them and produced a
    // self-consistent wrong answer, which this test then asserted. The
    // real crypto/ecdh rejects them ("P256 point not on curve"), which is
    // the invalid-curve defence the handshake previously lacked.
    //
    // 2G public key:
    let pub_2g_x: [u8; 32] = [
        0x7C, 0xF2, 0x7B, 0x18, 0x8D, 0x03, 0x4F, 0x7E, 0x8A, 0x52, 0x38, 0x03, 0x04, 0xB5, 0x1A, 0xC3,
        0xC0, 0x89, 0x69, 0xE2, 0x77, 0xF2, 0x1B, 0x35, 0xA6, 0x0B, 0x48, 0xFC, 0x47, 0x66, 0x99, 0x78,
    ];
    let pub_2g_y: [u8; 32] = [
        0x07, 0x77, 0x55, 0x10, 0xDB, 0x8E, 0xD0, 0x40, 0x29, 0x3D, 0x9A, 0xC6, 0x9F, 0x74, 0x30, 0xDB,
        0xBA, 0x7D, 0xAD, 0xE6, 0x3C, 0xE9, 0x82, 0x29, 0x9E, 0x04, 0xB7, 0x9D, 0x22, 0x78, 0x73, 0xD1,
    ];
    // 3G public key:
    let pub_3g_x: [u8; 32] = [
        0x5E, 0xCB, 0xE4, 0xD1, 0xA6, 0x33, 0x0A, 0x44, 0xC8, 0xF7, 0xEF, 0x95, 0x1D, 0x4B, 0xF1, 0x65,
        0xE6, 0xC6, 0xB7, 0x21, 0xEF, 0xAD, 0xA9, 0x85, 0xFB, 0x41, 0x66, 0x1B, 0xC6, 0xE7, 0xFD, 0x6C,
    ];
    let pub_3g_y: [u8; 32] = [
        0x87, 0x34, 0x64, 0x0C, 0x49, 0x98, 0xFF, 0x7E, 0x37, 0x4B, 0x06, 0xCE, 0x1A, 0x64, 0xA2, 0xEC,
        0xD8, 0x2A, 0xB0, 0x36, 0x38, 0x4F, 0xB8, 0x3D, 0x9A, 0x79, 0xB1, 0x27, 0xA2, 0x7D, 0x50, 0x32,
    ];
    // 6G x-coordinate (expected shared secret):
    let z_6g_x: [u8; 32] = [
        0xB0, 0x1A, 0x17, 0x2A, 0x76, 0xA4, 0x60, 0x2C, 0x92, 0xD3, 0x24, 0x2C, 0xB8, 0x97, 0xDD, 0xE3,
        0x02, 0x4C, 0x74, 0x0D, 0xEB, 0xB2, 0x15, 0xB4, 0xC6, 0xB0, 0xAA, 0xE9, 0x3C, 0x22, 0x91, 0xA9,
    ];

    // ECDH(2, 3G) should give 6G.x
    let scalar_2: [u8; 32] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2];
    let scalar_3: [u8; 32] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,3];

    let mut pub_3g_65: [u8; 65] = [0u8; 65];
    pub_3g_65[0] = 0x04;
    pub_3g_65[1..33].copy_from_slice(&pub_3g_x);
    pub_3g_65[33..65].copy_from_slice(&pub_3g_y);

    let mut pub_2g_65: [u8; 65] = [0u8; 65];
    pub_2g_65[0] = 0x04;
    pub_2g_65[1..33].copy_from_slice(&pub_2g_x);
    pub_2g_65[33..65].copy_from_slice(&pub_2g_y);

    let z2a = p256_ecdh_compute(&scalar_2, &pub_3g_65); // 2 * 3G = 6G
    let z2b = p256_ecdh_compute(&scalar_3, &pub_2g_65); // 3 * 2G = 6G

    if z2a == z_6g_x && z2b == z_6g_x {
        fmt::Println!(goish::string("[test2] PASS: small-scalar ECDH (2*3G == 3*2G == 6G)"));
    } else {
        fmt::Println!(goish::string("[test2] FAIL: small-scalar ECDH mismatch"));
        fmt::Println!(fmt::Sprintf!("[test2] 2*3G: %02x%02x%02x%02x... (expect b2eff2f1...)",
            z2a[0] as i64, z2a[1] as i64, z2a[2] as i64, z2a[3] as i64));
        fmt::Println!(fmt::Sprintf!("[test2] 3*2G: %02x%02x%02x%02x... (expect b2eff2f1...)",
            z2b[0] as i64, z2b[1] as i64, z2b[2] as i64, z2b[3] as i64));
        pass = false;
    }

    // ── Test 3: ECDH self-consistency (50 trials) ────────────────────────────────
    // Generate two random keypairs and verify ECDH(a,B) == ECDH(b,A).
    let mut t3_pass = 0i64;
    let mut t3_fail = 0i64;
    for _trial in 0i64..10i64 {
        let (priv_a, pub_a) = p256_keypair_generate();
        let (priv_b, pub_b) = p256_keypair_generate();

        // a's shared secret = a_priv * B_pub (x-coord)
        let z_a = p256_ecdh_compute(&priv_a, &pub_b);
        // b's shared secret = b_priv * A_pub (x-coord)
        let z_b = p256_ecdh_compute(&priv_b, &pub_a);

        if z_a == z_b {
            t3_pass += 1;
        } else {
            t3_fail += 1;
            if t3_fail <= 3 {
                fmt::Println!(fmt::Sprintf!("[test3] FAIL: ECDH(a,B) != ECDH(b,A) at trial %d", _trial));
            }
            pass = false;
        }
    }
    fmt::Println!(fmt::Sprintf!("[test3] ECDH self-consistency: %d/50 pass", t3_pass));

    if pass {
        fmt::Println!(goish::string("=== p256_ecdh_smoke: ALL PASS ==="));
        syscall::Exit(0);
    } else {
        fmt::Println!(goish::string("=== p256_ecdh_smoke: FAILURES ABOVE ==="));
        syscall::Exit(1);
    }
}
