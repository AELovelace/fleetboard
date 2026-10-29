//! The bearer-token check for `/stats`. One shared token, compared in constant time so the
//! comparison's timing can't leak how many leading characters were right.

use subtle::ConstantTimeEq;

/// True when `header` is `Bearer <expected>` (case-insensitive scheme, surrounding spaces ignored).
/// Lengths are compared first; a different length returns false at once, which is fine: the token's
/// length isn't a secret.
pub fn token_matches(header: Option<&str>, expected: &str) -> bool {
    let Some(value) = header else { return false };
    let value = value.trim();
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    let token = token.trim();
    if token.len() != expected.len() || expected.is_empty() {
        return false;
    }
    token.as_bytes().ct_eq(expected.as_bytes()).into() // constant-time byte comparison
}

#[cfg(test)]
mod tests {
    use super::*;

    // A plainly fake token (low entropy, so secret scanners don't mistake it for a real one).
    const T: &str = "test-token-test-token-test-token";

    #[test]
    fn accepts_the_right_token_in_any_scheme_case() {
        assert!(token_matches(Some(&format!("Bearer {T}")), T));
        assert!(token_matches(Some(&format!("bearer  {T} ")), T));
    }

    #[test]
    fn refuses_everything_else() {
        assert!(!token_matches(None, T));
        assert!(!token_matches(Some(T), T)); // no scheme
        assert!(!token_matches(Some(&format!("Basic {T}")), T)); // wrong scheme
        let one_off = format!("Bearer {}X", &T[..T.len() - 1]); // last character wrong
        assert!(!token_matches(Some(&one_off), T));
        assert!(!token_matches(Some("Bearer abc"), T)); // wrong length
        assert!(!token_matches(Some("Bearer "), "")); // an empty expected token never matches
    }
}
