// select_macro — Go's `select` statement as a Rust macro.
//
// Surface syntax (M16f-α):
//
//   select! {
//       let v = ch.Recv()        => body,    // bare ident drops `ok`
//       let (v, ok) = ch.Recv()  => body,    // tuple pat keeps both
//       let _ = ch.Recv()        => body,    // discard everything
//       let v = (expr).Recv()    => body,    // paren-expr fallback
//       ch.Send(x)               => body,    // ident-chan send
//       (expr).Send(x)           => body,    // paren-expr send
//       default                  => body,    // optional, any position
//   }
//
// Trailing comma optional. Each `body` is an `:expr` (block or
// one-liner); all bodies must produce the same type, which is the
// type of the whole `select!` expression. All chan operands and
// send right-hand-sides are evaluated exactly once, in source
// order, on entry (Go spec §Select).
//
// ─── Architecture: macro hygiene ──────────────────────────────────
//
// Per-case stack locals (chan handle, send-value Option, sudog) need
// stable names so different *passes* of the codegen can read what
// earlier passes wrote. macro_rules' hygiene means a literal
// `__ch_0` written in macro A and a literal `__ch_0` in macro B are
// *different* identifiers — they don't see each other's bindings.
//
// The fix: we generate all 32 per-case ident slots **once, in
// `select!`'s own body** (where they share `select!`'s hygiene),
// and pass them down to the parse + emit helpers as `:ident` macro
// parameters. Inside emit, each case uses its parser-assigned
// `$ch_name`, `$val_name`, `$sd_name` — all of which carry
// `select!`'s hygiene, so writes and reads see the same locals.
//
// The fixed cap of 32 cases is more than any realistic Go select
// (typical is 2–4). Exceeding it triggers a macro-cryptic error.
//
// ─── Codegen mirrors examples/select_handcoded.rs ─────────────────
//
//   - Pass-1: random Fisher-Yates poll order via cheaprandn,
//     each case's `__try_send` / `__try_recv` checked once. On a
//     hit, bind the user's pattern and `break 'select_blk` with
//     the body's value.
//   - Pass-2 (no default): stack-allocated `Sudog<T>`s registered
//     on every chan via `__register_*`, then `gopark`.
//   - Pass-2 (default present): break with default body.
//   - Pass-3: after wake, walk every sudog: `__cancel_*` returns
//     `false` for the popped one (winner). Bind + body + break.
//
// Cooperative single-M invariant: if pass-1 missed every case, no
// chan can be closed (otherwise `__try_*` would have caught it).
// `__register_*` failures in pass-2 are unreachable; we panic with
// a clear message rather than silently corrupt state. Multi-M
// (M16f-β / M17a) will need the full Go protocol.

// ─── select! ───────────────────────────────────────────────────────

/// Go's `select` statement. See the file-level docs for syntax.
#[macro_export]
macro_rules! select {
    () => {
        ::core::panic!("goish: select{} (block forever) — TODO M16f-α step 4c")
    };

    ($($arms:tt)*) => {{
        // Pre-allocate 32 per-case ident slots in *this* macro's
        // hygiene. The parse macro hands each non-default arm one
        // (idx, ch_name, val_name, sd_name) tuple from the head of
        // each list, embedding the idents in the parsed case so the
        // emit macro can `let $ch_name = ...` and later `$ch_name
        // .__try_recv()` referring to the same binding.
        $crate::__select_parse!(
            @parse
            [0u8 1u8 2u8 3u8 4u8 5u8 6u8 7u8
             8u8 9u8 10u8 11u8 12u8 13u8 14u8 15u8
             16u8 17u8 18u8 19u8 20u8 21u8 22u8 23u8
             24u8 25u8 26u8 27u8 28u8 29u8 30u8 31u8]
            [__sel_ch_0 __sel_ch_1 __sel_ch_2 __sel_ch_3
             __sel_ch_4 __sel_ch_5 __sel_ch_6 __sel_ch_7
             __sel_ch_8 __sel_ch_9 __sel_ch_10 __sel_ch_11
             __sel_ch_12 __sel_ch_13 __sel_ch_14 __sel_ch_15
             __sel_ch_16 __sel_ch_17 __sel_ch_18 __sel_ch_19
             __sel_ch_20 __sel_ch_21 __sel_ch_22 __sel_ch_23
             __sel_ch_24 __sel_ch_25 __sel_ch_26 __sel_ch_27
             __sel_ch_28 __sel_ch_29 __sel_ch_30 __sel_ch_31]
            [__sel_val_0 __sel_val_1 __sel_val_2 __sel_val_3
             __sel_val_4 __sel_val_5 __sel_val_6 __sel_val_7
             __sel_val_8 __sel_val_9 __sel_val_10 __sel_val_11
             __sel_val_12 __sel_val_13 __sel_val_14 __sel_val_15
             __sel_val_16 __sel_val_17 __sel_val_18 __sel_val_19
             __sel_val_20 __sel_val_21 __sel_val_22 __sel_val_23
             __sel_val_24 __sel_val_25 __sel_val_26 __sel_val_27
             __sel_val_28 __sel_val_29 __sel_val_30 __sel_val_31]
            [__sel_sd_0 __sel_sd_1 __sel_sd_2 __sel_sd_3
             __sel_sd_4 __sel_sd_5 __sel_sd_6 __sel_sd_7
             __sel_sd_8 __sel_sd_9 __sel_sd_10 __sel_sd_11
             __sel_sd_12 __sel_sd_13 __sel_sd_14 __sel_sd_15
             __sel_sd_16 __sel_sd_17 __sel_sd_18 __sel_sd_19
             __sel_sd_20 __sel_sd_21 __sel_sd_22 __sel_sd_23
             __sel_sd_24 __sel_sd_25 __sel_sd_26 __sel_sd_27
             __sel_sd_28 __sel_sd_29 __sel_sd_30 __sel_sd_31]
            [] [] [] []   // bare_recv, pat_recv, send, default accumulators
            $($arms)*
        )
    }};
}

// ─── parse phase ───────────────────────────────────────────────────
//
// TT-munching walker. Pops one (idx, ch_name, val_name, sd_name)
// from the head of the resource lists per non-default arm; embeds
// them in the parsed case tuple. When parsing finishes, hands four
// segregated case lists to `__select_emit!`.

#[doc(hidden)]
#[macro_export]
macro_rules! __select_parse {
    // ─── done ─────────────────────────────────────────────────────
    (@parse
     [$($_idx:tt)*] [$($_cn:ident)*] [$($_vn:ident)*] [$($_sn:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
    ) => {
        $crate::__select_emit!(
            [$($br)*] [$($pr)*] [$($snd)*] [$($d)*]
        )
    };

    // ─── recv: tuple-pat, paren chan ──────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let ( $($p:tt)+ ) = ( $ch:expr ) . Recv ( ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*]
            [$($pr)* (recv $idx $cn $vn $sn ($($p)+) ($ch) ($body))]
            [$($snd)*] [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let ( $($p:tt)+ ) = ( $ch:expr ) . Recv ( ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*]
            [$($pr)* (recv $idx $cn $vn $sn ($($p)+) ($ch) ($body))]
            [$($snd)*] [$($d)*]
        )
    };

    // ─── recv: tuple-pat, ident chan ──────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let ( $($p:tt)+ ) = $ch:ident . Recv ( ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*]
            [$($pr)* (recv $idx $cn $vn $sn ($($p)+) ($ch) ($body))]
            [$($snd)*] [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let ( $($p:tt)+ ) = $ch:ident . Recv ( ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*]
            [$($pr)* (recv $idx $cn $vn $sn ($($p)+) ($ch) ($body))]
            [$($snd)*] [$($d)*]
        )
    };

    // ─── recv: bare-tt, paren chan ────────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let $v:tt = ( $ch:expr ) . Recv ( ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)* (recv $idx $cn $vn $sn $v ($ch) ($body))]
            [$($pr)*] [$($snd)*] [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let $v:tt = ( $ch:expr ) . Recv ( ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)* (recv $idx $cn $vn $sn $v ($ch) ($body))]
            [$($pr)*] [$($snd)*] [$($d)*]
        )
    };

    // ─── recv: bare-tt, ident chan ────────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let $v:tt = $ch:ident . Recv ( ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)* (recv $idx $cn $vn $sn $v ($ch) ($body))]
            [$($pr)*] [$($snd)*] [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     let $v:tt = $ch:ident . Recv ( ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)* (recv $idx $cn $vn $sn $v ($ch) ($body))]
            [$($pr)*] [$($snd)*] [$($d)*]
        )
    };

    // ─── send: paren chan ─────────────────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     ( $ch:expr ) . Send ( $val:expr ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*] [$($pr)*]
            [$($snd)* (send $idx $cn $vn $sn ($ch) ($val) ($body))]
            [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     ( $ch:expr ) . Send ( $val:expr ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*] [$($pr)*]
            [$($snd)* (send $idx $cn $vn $sn ($ch) ($val) ($body))]
            [$($d)*]
        )
    };

    // ─── send: ident chan ─────────────────────────────────────────
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     $ch:ident . Send ( $val:expr ) => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*] [$($pr)*]
            [$($snd)* (send $idx $cn $vn $sn ($ch) ($val) ($body))]
            [$($d)*] $($rest)*
        )
    };
    (@parse
     [$idx:tt $($i_r:tt)*] [$cn:ident $($cn_r:ident)*] [$vn:ident $($vn_r:ident)*] [$sn:ident $($sn_r:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     $ch:ident . Send ( $val:expr ) => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i_r)*] [$($cn_r)*] [$($vn_r)*] [$($sn_r)*]
            [$($br)*] [$($pr)*]
            [$($snd)* (send $idx $cn $vn $sn ($ch) ($val) ($body))]
            [$($d)*]
        )
    };

    // ─── default ──────────────────────────────────────────────────
    (@parse
     [$($i:tt)*] [$($cn:ident)*] [$($vn:ident)*] [$($sn:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     default => $body:expr , $($rest:tt)*) => {
        $crate::__select_parse!(@parse
            [$($i)*] [$($cn)*] [$($vn)*] [$($sn)*]
            [$($br)*] [$($pr)*] [$($snd)*]
            [$($d)* (default ($body))]
            $($rest)*
        )
    };
    (@parse
     [$($i:tt)*] [$($cn:ident)*] [$($vn:ident)*] [$($sn:ident)*]
     [$($br:tt)*] [$($pr:tt)*] [$($snd:tt)*] [$($d:tt)*]
     default => $body:expr) => {
        $crate::__select_parse!(@parse
            [$($i)*] [$($cn)*] [$($vn)*] [$($sn)*]
            [$($br)*] [$($pr)*] [$($snd)*]
            [$($d)* (default ($body))]
        )
    };
}

// ─── emit phase (M16f-β) ──────────────────────────────────────────
//
// Multi-M-correct codegen: lock all chans up front (in sorted lock
// order, deduped), hold them across pass-1 + sudog-register, release
// via `selparkcommit` from inside `gopark`. Pass-3 (cancel + dispatch)
// is unchanged from α — each `__cancel_*` re-acquires its chan lock
// individually.
//
// Single arm so all per-case repetitions live inside one macro body
// (hygiene preservation — see file-level docs).

#[doc(hidden)]
#[macro_export]
macro_rules! __select_emit {
    (
        // bare-recv cases: (recv $idx $cn $vn $sn $v ($ch) ($body))
        [ $( ( recv $br_idx:tt $br_cn:ident $br_vn:ident $br_sn:ident $br_v:tt ($br_ch:expr) ($br_body:expr) ) )* ]
        // pat-recv cases: (recv $idx $cn $vn $sn (pat...) ($ch) ($body))
        [ $( ( recv $pr_idx:tt $pr_cn:ident $pr_vn:ident $pr_sn:ident ($($pr_p:tt)+) ($pr_ch:expr) ($pr_body:expr) ) )* ]
        // send cases: (send $idx $cn $vn $sn ($ch) ($val) ($body))
        [ $( ( send $s_idx:tt $s_cn:ident $s_vn:ident $s_sn:ident ($s_ch:expr) ($s_val:expr) ($s_body:expr) ) )* ]
        // 0 or 1 default arm.
        [ $( ( default ($d_body:expr) ) )* ]
    ) => {{
        // ─── async-preempt mask across the entire select! body ───
        // (FIRST statement so eval-once locals also run masked.)
        //
        // Pass-1's sort/dedup of `__sel_atoms` runs *before* any
        // `raw_lock`, so without this bump `m.locks == 0` and the
        // SIGURG handler is free to inject the async-preempt
        // trampoline anywhere in user code. Bumping m.locks masks
        // SIGURG injection until the matching `releasem()` at the
        // bottom of this block, after which pass-1 success
        // (`__select_release_all`), pass-2's `selparkcommit`, or
        // pass-3's per-`__cancel_*` raw_unlock have all returned.
        $crate::runtime::sched::acquirem();

        // ─── eval-once chan + send-val locals ────────────────────
        $( let $br_cn = ($br_ch).clone(); )*
        $( let $pr_cn = ($pr_ch).clone(); )*
        $( let $s_cn  = ($s_ch).clone(); )*
        $( let mut $s_vn: ::core::option::Option<_> =
                ::core::option::Option::Some($s_val); )*

        // Suppress lints on parser-allocated val slots that aren't
        // populated for recv cases.
        $( let _ = stringify!($br_vn); )*
        $( let _ = stringify!($pr_vn); )*

        // ─── case count (compile-time) ───────────────────────────
        const __SELECT_N: usize =
            <[u8]>::len(&[ $($br_idx,)* $($pr_idx,)* $($s_idx,)* ]);

        // ─── lock-order: collect lock atoms, sort, dedup ─────────
        //
        // M16f-β. Each chan's lock_atom is the address of its
        // SpinLock's `locked: AtomicBool` — Arc-stable for the
        // chan's lifetime. We sort distinct chans by atom address
        // and acquire all in that order before pass-1 even starts;
        // this is Go's runtime/select.go:206-240 lock-order sort.
        //
        // Nil chans contribute a null pointer to the array; the
        // sort floats nulls to the front and dedup compresses them
        // (at most one null after dedup). The lock-acquire loop
        // skips nulls — nil chans have no lock to take. Mirrors
        // Go's "Omit cases without channels from the poll and lock
        // orders" filter at runtime/select.go:173-177.
        //
        // Insertion sort is O(N²) but N ≤ 32 and array is on the
        // stack; no allocation, fits in cache.
        let mut __sel_atoms: [*const ::core::sync::atomic::AtomicBool; __SELECT_N] = [
            $( if $br_cn.is_nil() { ::core::ptr::null() } else { $br_cn.__lock_atom() }, )*
            $( if $pr_cn.is_nil() { ::core::ptr::null() } else { $pr_cn.__lock_atom() }, )*
            $( if $s_cn.is_nil()  { ::core::ptr::null() } else { $s_cn.__lock_atom()  }, )*
        ];
        {
            let mut __i: usize = 1;
            while __i < __SELECT_N {
                let mut __j: usize = __i;
                while __j > 0
                    && (__sel_atoms[__j - 1] as usize) > (__sel_atoms[__j] as usize)
                {
                    __sel_atoms.swap(__j - 1, __j);
                    __j -= 1;
                }
                __i += 1;
            }
        }
        // Compact distinct atoms to the front; track count.
        let mut __sel_unique: usize = 0;
        if __SELECT_N > 0 {
            __sel_unique = 1;
            let mut __i: usize = 1;
            while __i < __SELECT_N {
                if __sel_atoms[__i] != __sel_atoms[__sel_unique - 1] {
                    __sel_atoms[__sel_unique] = __sel_atoms[__i];
                    __sel_unique += 1;
                }
                __i += 1;
            }
        }

        // Acquire all distinct chan locks in sort order. Skip nulls
        // (nil chans).
        {
            let mut __i: usize = 0;
            while __i < __sel_unique {
                let __atom = __sel_atoms[__i];
                if !__atom.is_null() {
                    unsafe { $crate::runtime::spin::raw_lock(__atom); }
                }
                __i += 1;
            }
        }

        // ─── random poll order (Fisher-Yates inside-out) ─────────
        let mut __select_order: [u8; __SELECT_N] = [0u8; __SELECT_N];
        {
            let mut __i: usize = 0;
            while __i < __SELECT_N {
                let __j =
                    $crate::runtime::rand::cheaprandn((__i as u32) + 1) as usize;
                __select_order[__i] = __select_order[__j];
                __select_order[__j] = __i as u8;
                __i += 1;
            }
        }

        // ─── single labeled loop for the whole select ────────────
        let __select_out = 'select_blk: loop {
            // Pass-1: try each case in random order, under the
            // already-held chan locks. Use *_locked variants that
            // don't re-acquire.
            let mut __k: usize = 0;
            while __k < __SELECT_N {
                let __idx_val: u8 = __select_order[__k];

                $(
                    if __idx_val == $br_idx && !$br_cn.is_nil() {
                        let __s = unsafe { $br_cn.__state_unchecked() };
                        if let ::core::option::Option::Some((__v, __ok)) =
                            $crate::gochan::chan::__try_recv_locked(__s)
                        {
                            $crate::__select_release_all!(__sel_unique, __sel_atoms);
                            let _ = __ok;
                            let $br_v = __v;
                            #[allow(unreachable_code)]
                            break 'select_blk ({ $br_body });
                        }
                    }
                )*

                $(
                    if __idx_val == $pr_idx && !$pr_cn.is_nil() {
                        let __s = unsafe { $pr_cn.__state_unchecked() };
                        if let ::core::option::Option::Some((__v, __ok)) =
                            $crate::gochan::chan::__try_recv_locked(__s)
                        {
                            $crate::__select_release_all!(__sel_unique, __sel_atoms);
                            let ($($pr_p)+) = (__v, __ok);
                            #[allow(unreachable_code)]
                            break 'select_blk ({ $pr_body });
                        }
                    }
                )*

                $(
                    if __idx_val == $s_idx && !$s_cn.is_nil() {
                        let __take = $s_vn
                            .take()
                            .expect("goish: select pass-1 send value missing");
                        let __s = unsafe { $s_cn.__state_unchecked() };
                        match $crate::gochan::chan::__try_send_locked(__s, __take) {
                            ::core::result::Result::Ok(()) => {
                                $crate::__select_release_all!(__sel_unique, __sel_atoms);
                                #[allow(unreachable_code)]
                                break 'select_blk ({ $s_body });
                            }
                            ::core::result::Result::Err(__returned) => {
                                $s_vn = ::core::option::Option::Some(__returned);
                            }
                        }
                    }
                )*

                __k += 1;
            }

            // Pass-2: default body if present, else register-and-park.
            $crate::__select_default_or_park!(
                'select_blk,
                __sel_unique, __sel_atoms,
                [ $( $d_body )* ],
                [ $( ($br_idx $br_cn $br_sn $br_v ($br_body)) )* ]
                [ $( ($pr_idx $pr_cn $pr_sn ($($pr_p)+) ($pr_body)) )* ]
                [ $( ($s_idx $s_cn $s_vn $s_sn ($s_body)) )* ]
            );
        };
        // Matching `releasem()` for the `acquirem()` at the top of
        // this block. By this point all chan locks held during the
        // select! invocation have been released — pass-1 success →
        // `__select_release_all`; pass-2 → `selparkcommit`; pass-3
        // cancel → per-`__cancel_*` raw_unlock — so dropping
        // m.locks here re-arms async preempt for subsequent code.
        $crate::runtime::sched::releasem();
        __select_out
    }};
}

// ─── helper: release every distinct chan lock ─────────────────────

#[doc(hidden)]
#[macro_export]
macro_rules! __select_release_all {
    ($count:ident, $atoms:ident) => {{
        let mut __ui: usize = 0;
        while __ui < $count {
            let __atom = $atoms[__ui];
            if !__atom.is_null() {
                unsafe { $crate::runtime::spin::raw_unlock(__atom); }
            }
            __ui += 1;
        }
    }};
}

// ─── pass-2 dispatch: default present (1 expr) vs not (0 exprs) ──
//
// β: arm signature now also takes the unique-locked atoms (for
// release-all-on-default and for populating G.select_wait under
// no-default's gopark commit).

#[doc(hidden)]
#[macro_export]
macro_rules! __select_default_or_park {
    // ─── default present ─────────────────────────────────────────
    ( $blk:lifetime,
      $sel_unique:ident, $sel_atoms:ident,
      [ $d_body:expr ],
      [ $( ($br_idx:tt $br_cn:ident $br_sn:ident $br_v:tt ($br_body:expr)) )* ]
      [ $( ($pr_idx:tt $pr_cn:ident $pr_sn:ident ($($pr_p:tt)+) ($pr_body:expr)) )* ]
      [ $( ($s_idx:tt $s_cn:ident $s_vn:ident $s_sn:ident ($s_body:expr)) )* ]
    ) => {
        $crate::__select_release_all!($sel_unique, $sel_atoms);
        #[allow(unreachable_code)]
        break $blk ({ $d_body });
    };

    // ─── no default → register sudogs (under held locks), then
    //     gopark with selparkcommit (which releases all chan locks
    //     atomically with the park transition).
    ( $blk:lifetime,
      $sel_unique:ident, $sel_atoms:ident,
      [],
      [ $( ($br_idx:tt $br_cn:ident $br_sn:ident $br_v:tt ($br_body:expr)) )* ]
      [ $( ($pr_idx:tt $pr_cn:ident $pr_sn:ident ($($pr_p:tt)+) ($pr_body:expr)) )* ]
      [ $( ($s_idx:tt $s_cn:ident $s_vn:ident $s_sn:ident ($s_body:expr)) )* ]
    ) => {
        // Per-select coord on the stack.
        let __select_coord = $crate::gochan::SelectCoord::new();
        let __select_coord_ptr = ::core::ptr::NonNull::from(&__select_coord);
        let __select_g = $crate::runtime::sched::current_g()
            .expect("goish: select park outside any goroutine");

        // Stack-allocate one Sudog per case.
        $(
            let mut $br_sn: $crate::gochan::Sudog<_> =
                $crate::gochan::Sudog::new_recv_select(__select_g, __select_coord_ptr);
        )*
        $(
            let mut $pr_sn: $crate::gochan::Sudog<_> =
                $crate::gochan::Sudog::new_recv_select(__select_g, __select_coord_ptr);
        )*
        $(
            let __select_take = $s_vn
                .take()
                .expect("goish: select pass-2 send value missing");
            let mut $s_sn: $crate::gochan::Sudog<_> =
                $crate::gochan::Sudog::new_send_select(
                    __select_g, __select_take, __select_coord_ptr
                );
        )*

        // Register each sudog using the *_locked* helpers — we hold
        // every chan's lock from pass-1. β multi-M invariant: under
        // held locks, no other M can change a chan's state, so a
        // failure here means the chan was already closed before we
        // entered the select. In cooperative single-M this is
        // unreachable (pass-1 caught it); in multi-M it's a real
        // diagnostic. Panic with a clear message either way; future
        // refinement can synthesize the case-fired path.
        //
        // Nil chans are skipped: their cases never register a sudog
        // and contribute no atom to the held-lock set. Pass-3 cancel
        // also skips them.
        $(
            if !$br_cn.is_nil() {
                let __s = unsafe { $br_cn.__state_unchecked() };
                match $crate::gochan::chan::__register_recv_locked(__s, &mut $br_sn) {
                    $crate::gochan::RegisterStatus::Registered => {}
                    $crate::gochan::RegisterStatus::Closed => {
                        $crate::__select_release_all!($sel_unique, $sel_atoms);
                        ::core::panic!(
                            "goish: select pass-2 saw closed-and-empty under held lock"
                        );
                    }
                    $crate::gochan::RegisterStatus::Skip => {
                        // unreachable — nil chans guarded above
                    }
                }
            }
        )*
        $(
            if !$pr_cn.is_nil() {
                let __s = unsafe { $pr_cn.__state_unchecked() };
                match $crate::gochan::chan::__register_recv_locked(__s, &mut $pr_sn) {
                    $crate::gochan::RegisterStatus::Registered => {}
                    $crate::gochan::RegisterStatus::Closed => {
                        $crate::__select_release_all!($sel_unique, $sel_atoms);
                        ::core::panic!(
                            "goish: select pass-2 saw closed-and-empty under held lock"
                        );
                    }
                    $crate::gochan::RegisterStatus::Skip => {}
                }
            }
        )*
        $(
            if !$s_cn.is_nil() {
                let __s = unsafe { $s_cn.__state_unchecked() };
                match $crate::gochan::chan::__register_send_locked(__s, &mut $s_sn) {
                    $crate::gochan::RegisterStatus::Registered => {}
                    $crate::gochan::RegisterStatus::Closed => {
                        $crate::__select_release_all!($sel_unique, $sel_atoms);
                        ::core::panic!(
                            "goish: select pass-2 saw closed send chan under held lock"
                        );
                    }
                    $crate::gochan::RegisterStatus::Skip => {}
                }
            }
        )*

        // Stash a *pointer* to the parker's own `$sel_atoms` array
        // (already deduped/sorted, lives on this stack frame for the
        // entire park). selparkcommit walks via this pointer to
        // release locks in order — saves the 256 B inline copy on G.
        // The parker's stack frame stays live throughout `gopark`,
        // so the pointer is valid for the whole park transition.
        unsafe {
            let __g = &mut *__select_g.as_ptr();
            let __cap = $crate::runtime::sched::SELECT_WAIT_MAX;
            let __take_n = if $sel_unique > __cap { __cap } else { $sel_unique };
            __g.select_wait = $sel_atoms.as_ptr();
            __g.select_wait_len = __take_n as u8;
        }

        // Park. The commit fn (selparkcommit) walks G.select_wait
        // and releases every chan lock — this is the linearization
        // point at which our G is observably parked AND the chan
        // locks are released, so wakers can claim sudogs.
        // lock_atom is null: selparkcommit doesn't use M.waitlock
        // (it walks G.select_wait instead).
        $crate::runtime::sched::gopark(
            $crate::runtime::sched::selparkcommit,
            ::core::ptr::null(),
        );

        // Pass-3 step 1 — cancel every sudog. `__cancel_*` returns
        // `false` iff the sudog was already removed from its queue
        // by a waker (i.e., this case is the winner). We capture the
        // winner-bit per case into a fixed-size array indexed by the
        // case's declaration index, then dispatch in a separate flat
        // pass below.
        //
        // __SELECT_N is the case-count const computed earlier; the
        // array is local to this macro expansion. Indexes are
        // declaration-order u8s that fit in [0, __SELECT_N).
        let mut __select_winners: [bool; __SELECT_N] = [false; __SELECT_N];
        // Skip nil-chan cases: no sudog was registered, so they
        // can never be the winner. cancel_* on them would also be
        // a no-op but we'd misread the result.
        $( if !$br_cn.is_nil() {
                __select_winners[$br_idx as usize] =
                    !$br_cn.__cancel_recv(::core::ptr::NonNull::from(&$br_sn));
            }
        )*
        $( if !$pr_cn.is_nil() {
                __select_winners[$pr_idx as usize] =
                    !$pr_cn.__cancel_recv(::core::ptr::NonNull::from(&$pr_sn));
            }
        )*
        $( if !$s_cn.is_nil() {
                __select_winners[$s_idx as usize] =
                    !$s_cn.__cancel_send(::core::ptr::NonNull::from(&$s_sn));
            }
        )*

        // Pass-3 step 2 — dispatch the unique winner. Exactly one
        // case has its winner-bit set; the macro emits an if-chain
        // covering all cases. Each chain branch binds the user's
        // pattern (recv) or checks success (send) before breaking
        // with the body's value.
        $( if __select_winners[$br_idx as usize] {
                let __ok = $br_sn.success;
                let __v = $br_sn.value.take().unwrap_or_default();
                let _ = __ok;
                let $br_v = __v;
                #[allow(unreachable_code)]
                break $blk ({ $br_body });
            }
        )*
        $( if __select_winners[$pr_idx as usize] {
                let __ok = $pr_sn.success;
                let __v = $pr_sn.value.take().unwrap_or_default();
                let ($($pr_p)+) = (__v, __ok);
                #[allow(unreachable_code)]
                break $blk ({ $pr_body });
            }
        )*
        $( if __select_winners[$s_idx as usize] {
                if !$s_sn.success {
                    ::core::panic!("goish: select send winner: chan closed");
                }
                #[allow(unreachable_code)]
                break $blk ({ $s_body });
            }
        )*

        ::core::panic!("goish: select pass-3 found no winner");
    };
}
