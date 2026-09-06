// Port of net/dnsconfig.go + net/dnsconfig_unix.go @ Go 1.26.0
//
// DnsConfig holds parsed /etc/resolv.conf settings.
// dnsReadConfig reads and parses the resolv.conf file.

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_mut)]

extern crate alloc;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

// ─── DnsConfig ────────────────────────────────────────────────────────────

/// Parsed representation of /etc/resolv.conf. Mirrors Go's `dnsConfig`.
pub struct DnsConfig {
    /// Server addresses in "ip:port" form (up to 3).
    pub servers: Vec<String>,
    /// Rooted search-domain suffixes (each ends with '.').
    pub search: Vec<String>,
    /// ndots threshold (default 1).
    pub ndots: usize,
    /// Timeout in seconds per query attempt (default 5).
    pub timeout_secs: u64,
    /// Number of retry attempts per nameserver (default 2).
    pub attempts: usize,
    /// Whether to rotate through servers round-robin.
    pub rotate: bool,
    /// Use a single request (sequential A + AAAA) rather than parallel.
    ///
    /// Parsed from `options single-request` and never read, which is
    /// CORRECT rather than an oversight: `dnsclient.rs` issues A and
    /// AAAA in a plain loop over `&[TypeA, TypeAAAA]` with no
    /// goroutine, so the queries are already sequential and the option
    /// asks for what happens anyway. Go needs the flag because its
    /// resolver runs the two in parallel by default.
    ///
    /// Recorded here because a field that is set and never read is the
    /// shape of two real defects found in this tree — jsontext's
    /// AllowInvalidUTF8 and tls's skip_verify — so the next reader
    /// deserves to know which kind this one is.
    pub single_request: bool,
    /// Force TCP for DNS resolutions.
    pub use_tcp: bool,
    /// Add AD (authentic data) flag.
    pub trust_ad: bool,
    /// Do not reload from disk.
    ///
    /// Parsed from `options no-reload` and never read, and unlike
    /// `single_request` this one IS a divergence: `dnsclient.rs` calls
    /// `dns_read_config("/etc/resolv.conf")` on every lookup with no
    /// cache, so goish always reloads and a caller asking it not to is
    /// ignored. Go caches the config and honours the option.
    ///
    /// Left as-is rather than fixed because honouring it means adding
    /// the cache Go has, which is a behaviour change to every lookup
    /// rather than a flag read — but it is a divergence, not a no-op,
    /// and saying so is the point of this comment.
    pub no_reload: bool,
    /// Round-robin server offset counter.
    soffset: AtomicU32,
}

unsafe impl Send for DnsConfig {}
unsafe impl Sync for DnsConfig {}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            timeout_secs: 5,
            attempts: 2,
            rotate: false,
            single_request: false,
            use_tcp: false,
            trust_ad: false,
            no_reload: false,
            soffset: AtomicU32::new(0),
        }
    }
}

impl DnsConfig {
    /// Returns the current server offset and (if rotate=true) advances it.
    pub fn server_offset(&self) -> u32 {
        if self.rotate {
            self.soffset.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Build the FQDN list to query for the given name, applying
    /// search-domain expansion and ndots logic. Mirrors Go's
    /// `(*dnsConfig).nameList`.
    pub fn name_list<'a>(&self, name: &str) -> Vec<String> {
        let l = name.len();
        let rooted = l > 0 && name.as_bytes()[l - 1] == b'.';

        // Length check (mirrors Go's isDomainName length guard)
        if l > 254 || (l == 254 && !rooted) {
            return Vec::new();
        }

        if rooted {
            if avoid_dns(name) {
                return Vec::new();
            }
            return vec![name.to_owned()];
        }

        let dot_count = name.as_bytes().iter().filter(|&&b| b == b'.').count();
        let has_ndots = dot_count >= self.ndots;
        let abs = {
            let mut s = String::with_capacity(name.len() + 1);
            s.push_str(name);
            s.push('.');
            s
        };

        let mut names: Vec<String> = Vec::with_capacity(1 + self.search.len());

        // If name has enough dots, try unsuffixed absolute first.
        if has_ndots && !avoid_dns(&abs) {
            names.push(abs.clone());
        }
        // Try each search suffix.
        for suffix in &self.search {
            let fqdn = {
                let sfx = suffix.trim_start_matches('.');
                let mut s = String::with_capacity(name.len() + 1 + sfx.len() + 1);
                s.push_str(name);
                s.push('.');
                s.push_str(sfx);
                s
            };
            // Ensure trailing dot
            let fqdn = if fqdn.ends_with('.') {
                fqdn
            } else {
                let mut s = String::with_capacity(fqdn.len() + 1);
                s.push_str(&fqdn);
                s.push('.');
                s
            };
            if !avoid_dns(&fqdn) && fqdn.len() <= 254 {
                names.push(fqdn);
            }
        }
        // If not tried first above, try unsuffixed.
        if !has_ndots && !avoid_dns(&abs) {
            names.push(abs);
        }

        names
    }
}

/// avoidDNS reports whether this is a hostname for which we should not
/// use DNS. Matches Go's avoidDNS (only .onion per RFC 7686).
fn avoid_dns(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let name = name.trim_end_matches('.');
    has_suffix_fold(name, ".onion")
}

fn has_suffix_fold(s: &str, suffix: &str) -> bool {
    if s.len() < suffix.len() {
        return false;
    }
    let tail = &s[s.len() - suffix.len()..];
    tail.eq_ignore_ascii_case(suffix)
}

// ─── resolv.conf parser ───────────────────────────────────────────────────

/// Read and parse /etc/resolv.conf. Returns a DnsConfig with defaults
/// on any error reading the file. Mirrors Go's `dnsReadConfig`.
pub fn dns_read_config(filename: &str) -> DnsConfig {
    let mut conf = DnsConfig::default();

    // Read the file via raw syscall (no std fs in no_std).
    let content = match read_file_bytes(filename) {
        Some(b) => b,
        None => {
            conf.servers = default_nameservers();
            conf.search = dns_default_search();
            return conf;
        }
    };

    let text = match core::str::from_utf8(&content) {
        Ok(s) => s,
        Err(_) => {
            conf.servers = default_nameservers();
            conf.search = dns_default_search();
            return conf;
        }
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        match fields[0] {
            "nameserver" => {
                if fields.len() > 1 && conf.servers.len() < 3 {
                    // Validate it's an IP.
                    if is_ip(fields[1]) {
                        let ip = fields[1];
                        let mut s = String::with_capacity(ip.len() + 3);
                        s.push_str(ip);
                        s.push_str(":53");
                        conf.servers.push(s);
                    }
                }
            }
            "domain" => {
                if fields.len() > 1 {
                    conf.search = vec![ensure_rooted(fields[1])];
                }
            }
            "search" => {
                conf.search.clear();
                for &sf in &fields[1..] {
                    let name = ensure_rooted(sf);
                    if name != "." {
                        conf.search.push(name);
                    }
                }
            }
            "options" => {
                for &s in &fields[1..] {
                    if let Some(rest) = s.strip_prefix("ndots:") {
                        let mut n: usize = rest.parse().unwrap_or(conf.ndots);
                        if n > 15 {
                            n = 15;
                        }
                        conf.ndots = n;
                    } else if let Some(rest) = s.strip_prefix("timeout:") {
                        let n: u64 = rest.parse().unwrap_or(conf.timeout_secs);
                        conf.timeout_secs = n.max(1);
                    } else if let Some(rest) = s.strip_prefix("attempts:") {
                        let n: usize = rest.parse().unwrap_or(conf.attempts);
                        conf.attempts = n.max(1);
                    } else if s == "rotate" {
                        conf.rotate = true;
                    } else if s == "single-request" || s == "single-request-reopen" {
                        conf.single_request = true;
                    } else if s == "use-vc" || s == "usevc" || s == "tcp" {
                        conf.use_tcp = true;
                    } else if s == "trust-ad" {
                        conf.trust_ad = true;
                    } else if s == "no-reload" {
                        conf.no_reload = true;
                    }
                    // edns0 — ignored (we use EDNS by default)
                }
            }
            _ => {}
        }
    }

    if conf.servers.is_empty() {
        conf.servers = default_nameservers();
    }
    if conf.search.is_empty() {
        conf.search = dns_default_search();
    }
    conf
}

fn ensure_rooted(s: &str) -> String {
    if s.ends_with('.') {
        s.to_owned()
    } else {
        let mut r = String::with_capacity(s.len() + 1);
        r.push_str(s);
        r.push('.');
        r
    }
}

fn default_nameservers() -> Vec<String> {
    vec!["127.0.0.1:53".to_owned(), "[::1]:53".to_owned()]
}

fn dns_default_search() -> Vec<String> {
    // Try to get hostname from the kernel and extract domain part.
    let hn = get_hostname_bytes();
    if let Some(dot_pos) = hn.iter().position(|&b| b == b'.') {
        let rest = &hn[dot_pos + 1..];
        if !rest.is_empty() {
            if let Ok(s) = core::str::from_utf8(rest) {
                return vec![ensure_rooted(s)];
            }
        }
    }
    Vec::new()
}

/// Check if a string looks like an IPv4 or IPv6 address.
fn is_ip(s: &str) -> bool {
    // IPv4: digits and dots
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|p| p.parse::<u8>().is_ok());
        }
    }
    // IPv6: contains ':'
    if s.contains(':') {
        return true;
    }
    false
}

/// Read a file via raw syscall (works in no_std).
fn read_file_bytes(path: &str) -> Option<Vec<u8>> {
    // Construct a null-terminated path
    let mut path_bytes: Vec<u8> = path.as_bytes().to_vec();
    path_bytes.push(0);

    let fd = unsafe {
        crate::syscall::syscall3(crate::syscall::SYS_OPEN, path_bytes.as_ptr() as usize, 0, 0)
            as i32
    };
    if fd < 0 {
        return None;
    }

    let mut buf = vec![0u8; 8192];
    let n = unsafe {
        crate::syscall::syscall3(
            crate::syscall::SYS_READ,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
        ) as isize
    };
    let _ = unsafe { crate::syscall::syscall1(crate::syscall::SYS_CLOSE, fd as usize) };

    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// Get hostname via uname syscall, return bytes up to null terminator.
fn get_hostname_bytes() -> Vec<u8> {
    // Linux uname syscall (63 on x86-64).
    // struct utsname has 6 fields each 65 bytes.
    // nodename is at offset 65 bytes.
    let mut buf = [0u8; 65 * 6];
    unsafe {
        crate::syscall::syscall1(crate::syscall::SYS_UNAME, buf.as_mut_ptr() as usize);
    }
    // nodename is the 2nd field
    let nodename = &buf[65..130];
    let end = nodename.iter().position(|&b| b == 0).unwrap_or(65);
    nodename[..end].to_vec()
}
