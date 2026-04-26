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

// ─── emit phase ────────────────────────────────────────────────────
//
// Single arm — all per-case repetitions live inside one macro
// body, so identifier hygiene is preserved across passes.
// The `[$($d:tt)?]` would be ideal for "0 or 1 default" but `?`
// in macro_rules patterns isn't allowed for tts-blocks; we use
// `[$($d:tt)*]` (0 or more) and a sub-helper to dispatch on
// presence/absence of a default arm.

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
        // ─── eval-once chan + send-val locals ────────────────────
        $( let $br_cn = ($br_ch).clone(); )*
        $( let $pr_cn = ($pr_ch).clone(); )*
        $( let $s_cn  = ($s_ch).clone(); )*
        $( let mut $s_vn: ::core::option::Option<_> =
                ::core::option::Option::Some($s_val); )*

        // Suppress "value never read" / "unused mut" lints for
        // recv val-name slots that aren't a send case. The val_name
        // for recv cases is reserved by the parser but never used
        // in emit; just discard it via `_`.
        $( let _ = stringify!($br_vn); )*
        $( let _ = stringify!($pr_vn); )*

        // ─── case count (compile-time) ───────────────────────────
        const __SELECT_N: usize =
            <[u8]>::len(&[ $($br_idx,)* $($pr_idx,)* $($s_idx,)* ]);

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
            // Pass-1: try each case in random order.
            let mut __k: usize = 0;
            while __k < __SELECT_N {
                let __idx_val: u8 = __select_order[__k];

                $(
                    if __idx_val == $br_idx {
                        if let ::core::option::Option::Some((__v, __ok)) =
                            $br_cn.__try_recv()
                        {
                            let _ = __ok;
                            let $br_v = __v;
                            break 'select_blk $br_body;
                        }
                    }
                )*

                $(
                    if __idx_val == $pr_idx {
                        if let ::core::option::Option::Some((__v, __ok)) =
                            $pr_cn.__try_recv()
                        {
                            let ($($pr_p)+) = (__v, __ok);
                            break 'select_blk $pr_body;
                        }
                    }
                )*

                $(
                    if __idx_val == $s_idx {
                        let __take = $s_vn
                            .take()
                            .expect("goish: select pass-1 send value missing");
                        match $s_cn.__try_send(__take) {
                            ::core::result::Result::Ok(()) =>
                                break 'select_blk $s_body,
                            ::core::result::Result::Err(__returned) => {
                                $s_vn = ::core::option::Option::Some(__returned);
                            }
                        }
                    }
                )*

                __k += 1;
            }

            // Pass-2: default body if any case in [$($d)*] was parsed,
            // else park + pass-3.
            $crate::__select_default_or_park!(
                'select_blk,
                [ $( $d_body )* ],
                // bare-recv
                [ $( ($br_idx $br_cn $br_sn $br_v ($br_body)) )* ]
                // pat-recv
                [ $( ($pr_idx $pr_cn $pr_sn ($($pr_p)+) ($pr_body)) )* ]
                // send
                [ $( ($s_idx $s_cn $s_vn $s_sn ($s_body)) )* ]
            );
        };
        __select_out
    }};
}

// ─── pass-2 dispatch: default present (1 expr) vs not (0 exprs) ──
//
// macro_rules can match "exactly one" via a literal arm and "zero"
// via another. We bracket the default body list `[ $($d:tt)* ]` and
// use two arms.

#[doc(hidden)]
#[macro_export]
macro_rules! __select_default_or_park {
    // ─── default present ─────────────────────────────────────────
    ( $blk:lifetime, [ $d_body:expr ],
      [ $( ($br_idx:tt $br_cn:ident $br_sn:ident $br_v:tt ($br_body:expr)) )* ]
      [ $( ($pr_idx:tt $pr_cn:ident $pr_sn:ident ($($pr_p:tt)+) ($pr_body:expr)) )* ]
      [ $( ($s_idx:tt $s_cn:ident $s_vn:ident $s_sn:ident ($s_body:expr)) )* ]
    ) => {
        break $blk $d_body;
    };

    // ─── no default → register sudogs, park, pass-3 ──────────────
    ( $blk:lifetime, [],
      [ $( ($br_idx:tt $br_cn:ident $br_sn:ident $br_v:tt ($br_body:expr)) )* ]
      [ $( ($pr_idx:tt $pr_cn:ident $pr_sn:ident ($($pr_p:tt)+) ($pr_body:expr)) )* ]
      [ $( ($s_idx:tt $s_cn:ident $s_vn:ident $s_sn:ident ($s_body:expr)) )* ]
    ) => {
        // Per-select shared coordination state on the stack.
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

        // Register each sudog. Cooperative invariant: register must
        // succeed (pass-1 already caught any closed chan); panic if
        // it doesn't.
        $(
            if $br_cn.__register_recv(&mut $br_sn).is_err() {
                ::core::panic!(
                    "goish: select pass-2 saw closed-and-empty (cooperative invariant)"
                );
            }
        )*
        $(
            if $pr_cn.__register_recv(&mut $pr_sn).is_err() {
                ::core::panic!(
                    "goish: select pass-2 saw closed-and-empty (cooperative invariant)"
                );
            }
        )*
        $(
            if !$s_cn.__register_send(&mut $s_sn) {
                ::core::panic!(
                    "goish: select pass-2 saw closed send chan (cooperative invariant)"
                );
            }
        )*

        $crate::runtime::sched::gopark(|| true);

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
        $( __select_winners[$br_idx as usize] =
                !$br_cn.__cancel_recv(::core::ptr::NonNull::from(&$br_sn)); )*
        $( __select_winners[$pr_idx as usize] =
                !$pr_cn.__cancel_recv(::core::ptr::NonNull::from(&$pr_sn)); )*
        $( __select_winners[$s_idx as usize]  =
                !$s_cn.__cancel_send(::core::ptr::NonNull::from(&$s_sn)); )*

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
                break $blk $br_body;
            }
        )*
        $( if __select_winners[$pr_idx as usize] {
                let __ok = $pr_sn.success;
                let __v = $pr_sn.value.take().unwrap_or_default();
                let ($($pr_p)+) = (__v, __ok);
                break $blk $pr_body;
            }
        )*
        $( if __select_winners[$s_idx as usize] {
                if !$s_sn.success {
                    ::core::panic!("goish: select send winner: chan closed");
                }
                break $blk $s_body;
            }
        )*

        ::core::panic!("goish: select pass-3 found no winner");
    };
}
