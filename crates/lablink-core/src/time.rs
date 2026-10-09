//! Wall-clock helpers. All persisted timestamps are Unix epoch milliseconds.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Human-readable age, e.g. `<1s`, `42s`, `4m`, `3h`, `2d`.
pub fn format_age(age_ms: u64) -> String {
    let s = age_ms / 1000;
    if s < 1 {
        "<1s".into()
    } else if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h", s / 3600)
    } else {
        format!("{}d", s / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_formatting() {
        assert_eq!(format_age(0), "<1s");
        assert_eq!(format_age(999), "<1s");
        assert_eq!(format_age(1_000), "1s");
        assert_eq!(format_age(240_000), "4m");
        assert_eq!(format_age(7_200_000), "2h");
        assert_eq!(format_age(172_800_000), "2d");
    }
}
