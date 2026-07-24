// Package locale — ported from typescript-go internal/locale.

use goish::context;
use goish::gostring::string;
use goish::text::language;

use alloc::sync::Arc;

/// Locale is a language.Tag newtype (Go: `type Locale language.Tag`).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Locale(pub language::Tag);

pub fn Default() -> Locale {
    Locale(language::Und)
}

// goish context::WithValue keys by string (Go's any-typed keys map to
// a package-unique string; "tsgoish.locale" mirrors contextKey(0)).
const CONTEXT_KEY: &str = "tsgoish.locale.contextKey0";

pub fn WithLocale(
    ctx: Arc<dyn context::Context>,
    locale: Locale,
) -> Arc<dyn context::Context> {
    context::WithValue(ctx, CONTEXT_KEY, locale)
}

pub fn FromContext(ctx: &Arc<dyn context::Context>) -> Locale {
    // Go: locale, _ := ctx.Value(contextKey(0)).(Locale)
    match ctx.Value(CONTEXT_KEY) {
        Some(v) => match v.downcast_ref::<Locale>() {
            Some(l) => l.clone(),
            None => Locale::default(),
        },
        None => Locale::default(),
    }
}

pub fn Parse<S: AsRef<str>>(locale_str: S) -> (Locale, bool) {
    // Parse gracefully fails.
    let (tag, err) = language::Parse(locale_str);
    (Locale(tag), err == goish::nil)
}

impl Locale {
    pub fn String(&self) -> string {
        self.0.String()
    }
}
