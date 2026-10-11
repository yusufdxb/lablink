//! Hotspot passwords (WPA pre-shared keys) and SSIDs.
//!
//! Generated passwords: 24 characters from a 32-character alphabet without
//! look-alikes (no 0/o, 1/l), from the OS CSPRNG, shown in groups of four:
//! 120 bits, easy to read aloud and type on a phone. A password the user
//! supplies is read from stdin, never from the command line, and limited to
//! characters NetworkManager's editor takes literally.

use crate::system::System;

const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
pub const GENERATED_CHARS: usize = 24;
pub const MIN_USER_LEN: usize = 12;

pub fn generate(sys: &dyn System) -> std::io::Result<String> {
    let mut bytes = [0u8; GENERATED_CHARS];
    sys.random(&mut bytes)?;
    // 256 is a multiple of 32: masking is unbiased.
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    Ok(chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

/// Check a user-supplied password. Returns the reason it is refused.
pub fn validate_user(psk: &str) -> Result<(), String> {
    if psk.len() < MIN_USER_LEN {
        return Err(format!(
            "too short: use at least {MIN_USER_LEN} characters (or let LabLink generate one)"
        ));
    }
    if psk.len() > 63 {
        return Err("too long: WPA passwords are at most 63 characters".into());
    }
    if let Some(c) = psk
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "-_.,:;!@#%^&*+=?~/()[]{}<>|$".contains(*c)))
    {
        return Err(format!(
            "character {c:?} is not allowed (letters, digits and -_.,:;!@#%^&*+=?~/()[]{{}}<>|$ only; no spaces, quotes or backslashes)"
        ));
    }
    Ok(())
}

/// An SSID LabLink will configure: 1-32 bytes of letters, digits, space,
/// `-`, `_` and `.`, not starting or ending with a space. Stricter than
/// 802.11 so it can never break out of an editor line or a terminal.
pub fn validate_ssid(ssid: &str) -> Result<(), String> {
    if !lablink_core::config::valid_ssid(ssid) {
        return Err("an SSID is 1-32 bytes without control characters".into());
    }
    if ssid.starts_with(' ') || ssid.ends_with(' ') {
        return Err("an SSID must not start or end with a space".into());
    }
    if let Some(c) = ssid
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || " -_.".contains(*c)))
    {
        return Err(format!(
            "character {c:?} is not allowed in a LabLink SSID (letters, digits, space, - _ . only)"
        ));
    }
    Ok(())
}

/// The default SSID: "LabLink-" and four characters derived from the
/// machine id, stable across starts, revealing nothing about the user.
pub fn default_ssid(sys: &dyn System) -> String {
    let id = sys
        .read_file(std::path::Path::new("/etc/machine-id"))
        .unwrap_or_default();
    let mut h: u32 = 2166136261;
    for b in id.trim().bytes() {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    let tag: String = (0..4)
        .map(|i| ALPHABET[((h >> (i * 5)) & 31) as usize] as char)
        .collect();
    format!("LabLink-{}", tag.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{FakeSystem, RealSystem};

    #[test]
    fn generated_passwords_are_long_unambiguous_and_random() {
        let a = generate(&RealSystem).unwrap();
        let b = generate(&RealSystem).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), GENERATED_CHARS + GENERATED_CHARS / 4 - 1);
        assert!(validate_user(&a).is_ok());
        assert!(!a.chars().any(|c| "01lo".contains(c)));
        assert_eq!(a.split('-').count(), 6);
    }

    #[test]
    fn user_passwords() {
        assert!(validate_user("short").unwrap_err().contains("too short"));
        assert!(validate_user(&"a".repeat(64))
            .unwrap_err()
            .contains("too long"));
        assert!(validate_user("has a space in it").is_err());
        assert!(validate_user("line\nbreak-injection").is_err());
        assert!(validate_user("back\\slash12345").is_err());
        assert!(validate_user("quote\"d12345678").is_err());
        assert!(validate_user("Correct-Horse_42!").is_ok());
    }

    #[test]
    fn ssids_cannot_inject_editor_lines() {
        assert!(validate_ssid("LabLink Field").is_ok());
        assert!(validate_ssid("x\nsave persistent").is_err());
        assert!(validate_ssid(" lead").is_err());
        assert!(validate_ssid("emoji\u{1F600}").is_err());
        assert!(validate_ssid(&"a".repeat(33)).is_err());
        assert!(validate_ssid("").is_err());
    }

    #[test]
    fn default_ssid_is_stable_per_machine() {
        let f = FakeSystem::new();
        f.file("/etc/machine-id", "0123456789abcdef0123456789abcdef\n");
        let a = default_ssid(&f);
        assert_eq!(a, default_ssid(&f));
        assert!(a.starts_with("LabLink-") && a.len() == 12);
        assert!(validate_ssid(&a).is_ok());
        f.file("/etc/machine-id", "ffffffffffffffffffffffffffffffff\n");
        assert_ne!(a, default_ssid(&f));
    }
}
