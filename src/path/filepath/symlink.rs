// go: file path/filepath/symlink.go decls: walkSymlinks
//
// symlink.go — EvalSymlinks and the walk behind it.

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::gostring::string;

use super::*;

// ─── EvalSymlinks ─────────────────────────────────────────────────────

// go: sdk 1.25.5 path/filepath/symlink.go:16-150 walkSymlinks
/// Line-by-line port of `path/filepath.EvalSymlinks` (path.go:147 →
/// symlink.go:16 walkSymlinks). Walks each component of `path`, calling
/// os.Lstat to detect symlinks and os.Readlink to resolve them. Caps
/// chain length at 255 to bail on cycles. Linux slim: no Windows volume
/// handling, no plan9 branch.
// goishlint:ignore GOISH014 - the anchor names the GO symbol; goish
//     spells package-internal helpers in snake_case.
pub(super) fn walk_symlinks(path0: string) -> (string, error) {
    // Go: volLen := filepathlite.VolumeNameLen(path) — Linux: 0.
    let mut path = path0;
    let vol_len: usize = 0;
    let _ = vol_len; // Linux: always 0; kept for parity.
                     // Go: if volLen < len(path) && os.IsPathSeparator(path[volLen]) { volLen++ }
    let pb = path.as_bytes();
    let mut vol_len_eff: usize = 0;
    if vol_len_eff < pb.len() && pb[vol_len_eff] == Separator {
        vol_len_eff += 1;
    }
    // Go: vol := path[:volLen]; dest := vol
    let vol_slice = &path.as_bytes()[..vol_len_eff];
    let mut dest: Vec<u8> = vol_slice.to_vec();
    let mut links_walked: i32 = 0;
    // Go: for start, end := volLen, volLen; start < len(path); start = end { ... }
    let mut start: usize = vol_len_eff;
    let mut end: usize;
    loop {
        let pb = path.as_bytes();
        if start >= pb.len() {
            break;
        }
        // Go: for start < len(path) && os.IsPathSeparator(path[start]) { start++ }
        while start < pb.len() && pb[start] == Separator {
            start += 1;
        }
        end = start;
        // Go: for end < len(path) && !os.IsPathSeparator(path[end]) { end++ }
        while end < pb.len() && pb[end] != Separator {
            end += 1;
        }
        // Go: if end == start { break }
        if end == start {
            break;
        }
        let comp = &pb[start..end];
        // Go: else if path[start:end] == "." { continue }
        if comp == b"." {
            start = end;
            continue;
        }
        // Go: else if path[start:end] == ".." { ... back up ... }
        if comp == b".." {
            // Go: for r = len(dest)-1; r >= volLen; r-- { ... }
            let mut r: isize = dest.len() as isize - 1;
            while r >= vol_len_eff as isize {
                if dest[r as usize] == Separator {
                    break;
                }
                r -= 1;
            }
            // Go: if r < volLen || dest[r+1:] == ".."
            let tail_is_dotdot =
                (r + 1) <= dest.len() as isize && &dest[(r + 1) as usize..] == b"..";
            if r < vol_len_eff as isize || tail_is_dotdot {
                // Go: if len(dest) > volLen { dest += pathSeparator }
                if dest.len() > vol_len_eff {
                    dest.push(Separator);
                }
                // Go: dest += ".."
                dest.extend_from_slice(b"..");
            } else {
                // Go: dest = dest[:r]
                dest.truncate(r as usize);
            }
            start = end;
            continue;
        }
        // Ordinary path component. Add it to result.
        // Go: if len(dest) > VolumeNameLen(dest) && !IsPathSeparator(dest[last]) { dest += pathSeparator }
        if dest.len() > vol_len_eff && (dest.is_empty() || dest[dest.len() - 1] != Separator) {
            dest.push(Separator);
        }
        // Go: dest += path[start:end]
        dest.extend_from_slice(comp);
        // Resolve symlink.
        // Go: fi, err := os.Lstat(dest)
        let dest_s = string::from_bytes(&dest);
        let (fi, err) = crate::os::Lstat(dest_s.clone());
        if !err.IsNil() {
            return (string::new(), err);
        }
        // Go: if fi.Mode()&fs.ModeSymlink == 0 { ... continue }
        if (fi.Mode() & crate::os::ModeSymlink) == 0 {
            // Go: if !fi.Mode().IsDir() && end < len(path) { return "", syscall.ENOTDIR }
            if !fi.IsDir() && end < path.as_bytes().len() {
                return (
                    string::new(),
                    errors::New(string::from_static("not a directory")),
                );
            }
            start = end;
            continue;
        }
        // Found symlink.
        links_walked += 1;
        // Go: if linksWalked > 255 { return "", errors.New("EvalSymlinks: too many links") }
        if links_walked > 255 {
            return (
                string::new(),
                errors::New(string::from_static("EvalSymlinks: too many links")),
            );
        }
        // Go: link, err := os.Readlink(dest)
        let (link, err) = crate::os::Readlink(dest_s);
        if !err.IsNil() {
            return (string::new(), err);
        }
        let lb = link.as_bytes();
        // Go: path = link + path[end:]
        let mut new_path: Vec<u8> = Vec::with_capacity(lb.len() + path.as_bytes().len() - end);
        new_path.extend_from_slice(lb);
        new_path.extend_from_slice(&path.as_bytes()[end..]);
        path = string::from_bytes(&new_path);
        // Go: v := VolumeNameLen(link); if v > 0 { ... } else if abs { ... } else { ... }
        // Linux slim: v always 0.
        if !lb.is_empty() && lb[0] == Separator {
            // Symlink to absolute path.
            // Go: dest = link[:1]; end = 1; vol = link[:1]; volLen = 1
            dest = alloc::vec::Vec::new();
            dest.push(Separator);
            end = 1;
            vol_len_eff = 1;
        } else {
            // Symlink to relative path; replace last path component in dest.
            // Go: for r = len(dest)-1; r >= volLen; r-- { if IsPathSeparator { break } }
            let mut r: isize = dest.len() as isize - 1;
            while r >= vol_len_eff as isize {
                if dest[r as usize] == Separator {
                    break;
                }
                r -= 1;
            }
            // Go: if r < volLen { dest = vol } else { dest = dest[:r] }
            if r < vol_len_eff as isize {
                dest.truncate(vol_len_eff);
            } else {
                dest.truncate(r as usize);
            }
            end = 0;
        }
        start = end;
    }
    // Go: return Clean(dest), nil
    return (Clean(string::from_bytes(&dest)), nil);
}
