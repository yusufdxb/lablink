//! Secrets that ROS 2 and DDS settings can carry, removed from text before
//! LabLink shows it: DDS Security private keys (PEM blocks, `data:,` values),
//! passwords, and PKCS#11 PINs, whether in inline `CYCLONEDDS_URI` XML, a
//! shell startup line or a Fast DDS property. The raw values stay inside
//! LabLink only where a device's own setting is passed back to that device;
//! everything printed, returned as JSON or shown in the app is redacted.

/// What a removed secret is replaced with.
pub const MARK: &str = "[redacted]";

/// Element names (case-insensitive, namespace prefix ignored) whose content
/// is secret: Cyclone DDS `Security/Authentication/PrivateKey` and
/// `Password`, and the obvious spellings elsewhere.
const SECRET_ELEMENTS: &[&str] = &["privatekey", "private_key", "password", "pin", "passphrase"];

/// Fast DDS property names containing one of these have a secret `<value>`.
const SECRET_PROPERTIES: &[&str] = &["private_key", "password", "passphrase", "pin"];

/// `s` with every recognized secret replaced by [`MARK`]. Idempotent, and
/// text without secrets comes back unchanged.
pub fn redact_secrets(s: &str) -> String {
    let s = redact_pem(s);
    let s = redact_elements(&s);
    let s = redact_properties(&s);
    redact_pin(&s)
}

/// Every string inside `v`, redacted in place.
pub fn redact_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            let r = redact_secrets(s);
            if r != *s {
                *s = r;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(redact_json),
        serde_json::Value::Object(o) => o.values_mut().for_each(redact_json),
        _ => {}
    }
}

/// Case-insensitive find of an ASCII `needle` in `hay` from byte `from`.
/// Lowercasing ASCII keeps byte offsets, so indexes are valid in `hay`.
fn find_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || from > h.len() || h.len() - from < n.len() {
        return None;
    }
    (from..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// PEM private keys (`-----BEGIN ... PRIVATE KEY-----` to the matching END,
/// or to the end of the text when it was cut short).
fn redact_pem(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(b) = find_ci(s, "-----BEGIN ", i) {
        let label_end = match s[b + 11..].find("-----") {
            Some(e) => b + 11 + e,
            None => break,
        };
        let label = &s[b + 11..label_end];
        if !label.to_ascii_uppercase().contains("PRIVATE KEY") {
            out.push_str(&s[i..label_end + 5]);
            i = label_end + 5;
            continue;
        }
        out.push_str(&s[i..b]);
        out.push_str(MARK);
        i = match find_ci(s, "-----END ", label_end + 5) {
            Some(e) => match s[e + 9..].find("-----") {
                Some(t) => e + 9 + t + 5,
                None => s.len(),
            },
            None => s.len(),
        };
    }
    out.push_str(&s[i..]);
    out
}

/// The content of secret XML elements (`<PrivateKey>...</PrivateKey>`).
fn redact_elements(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut scan = 0;
    while let Some(lt) = s[scan..].find('<').map(|p| scan + p) {
        let name_end = s[lt + 1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || "_:.-".contains(c)))
            .map(|p| lt + 1 + p)
            .unwrap_or(s.len());
        let name = &s[lt + 1..name_end];
        let local = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
        let Some(gt) = s[name_end..].find('>').map(|p| name_end + p) else {
            break;
        };
        if name.is_empty() || s[..gt].ends_with('/') || !SECRET_ELEMENTS.contains(&local.as_str()) {
            scan = lt + 1;
            continue;
        }
        let close = find_ci(s, &format!("</{name}"), gt + 1);
        out.push_str(&s[i..=gt]);
        out.push_str(MARK);
        match close {
            Some(c) => {
                i = c;
                scan = c + 2;
            }
            None => {
                i = s.len();
                break;
            }
        }
    }
    out.push_str(&s[i.min(s.len())..]);
    out
}

/// Fast DDS `<property><name>...private_key</name><value>SECRET</value>`.
fn redact_properties(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut scan = 0;
    while let Some(n) = find_ci(s, "<name>", scan) {
        let Some(ne) = find_ci(s, "</name>", n + 6) else {
            break;
        };
        scan = ne + 7;
        let name = s[n + 6..ne].to_ascii_lowercase();
        if !SECRET_PROPERTIES.iter().any(|k| name.contains(k)) {
            continue;
        }
        let Some(v) = find_ci(s, "<value>", scan) else {
            continue;
        };
        // The value must belong to this property, not a later one.
        let next_name = find_ci(s, "<name>", scan).unwrap_or(usize::MAX);
        if v > next_name {
            continue;
        }
        let ve = find_ci(s, "</value>", v + 7).unwrap_or(s.len());
        out.push_str(&s[i..v + 7]);
        out.push_str(MARK);
        i = ve;
        scan = ve;
    }
    out.push_str(&s[i..]);
    out
}

/// PKCS#11 URI PINs: `pin-value=1234`.
fn redact_pin(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(p) = find_ci(s, "pin-value=", i) {
        let start = p + 10;
        let end = s[start..]
            .find(|c: char| ";&<>\"' \t\r\n".contains(c))
            .map(|e| start + e)
            .unwrap_or(s.len());
        out.push_str(&s[i..start]);
        out.push_str(MARK);
        i = end;
    }
    out.push_str(&s[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";

    #[test]
    fn cyclone_inline_security_keys_and_passwords_are_removed() {
        let x = format!(
            "<CycloneDDS><Domain><Security><Authentication>\
             <IdentityCertificate>file:/k/cert.pem</IdentityCertificate>\
             <PrivateKey>data:,-----BEGIN PRIVATE KEY-----\n{KEY}\n-----END PRIVATE KEY-----</PrivateKey>\
             <Password>hunter2</Password></Authentication></Security></Domain></CycloneDDS>"
        );
        let r = redact_secrets(&x);
        assert!(!r.contains(KEY) && !r.contains("hunter2"), "{r}");
        assert!(r.contains("<PrivateKey>[redacted]</PrivateKey>"), "{r}");
        assert!(r.contains("<Password>[redacted]</Password>"), "{r}");
        assert!(
            r.contains("file:/k/cert.pem"),
            "public parts stay visible: {r}"
        );
        assert_eq!(redact_secrets(&r), r, "idempotent");
    }

    #[test]
    fn fast_dds_secret_properties_are_removed() {
        let x = "<property><name>dds.sec.auth.builtin.PKI-DH.identity_ca</name><value>file:ca.pem</value></property>\
                 <property><name>dds.sec.auth.builtin.PKI-DH.private_key</name><value>file:/k/key.pem</value></property>\
                 <property><name>dds.sec.auth.builtin.PKI-DH.password</name>\n <value>s3cret</value></property>";
        let r = redact_secrets(x);
        assert!(!r.contains("/k/key.pem") && !r.contains("s3cret"), "{r}");
        assert!(r.contains("file:ca.pem"), "{r}");
        assert_eq!(redact_secrets(&r), r);
    }

    #[test]
    fn pins_pem_blocks_and_cut_off_text() {
        let r = redact_secrets("pkcs11:token=ros;object=key?pin-value=1234&module=x");
        assert_eq!(
            r,
            "pkcs11:token=ros;object=key?pin-value=[redacted]&module=x"
        );
        // Cut off by the remote script's length limit: nothing after BEGIN shows.
        let r = redact_secrets(&format!("x -----BEGIN EC PRIVATE KEY-----\n{KEY}"));
        assert_eq!(r, "x [redacted]");
        let r = redact_secrets(&format!("<PrivateKey>{KEY}"));
        assert!(!r.contains(KEY), "{r}");
        // Certificates are public.
        let c = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(redact_secrets(c), c);
    }

    #[test]
    fn ordinary_settings_are_unchanged() {
        for s in [
            "<CycloneDDS><Domain><General><NetworkInterfaceAddress>wlan0</NetworkInterfaceAddress></General></Domain></CycloneDDS>",
            "file:///home/u/cyclone.xml",
            "<Peers><Peer address=\"10.0.0.2\"/></Peers>",
            "<a/><pin/>",
            "",
            "rmw_cyclonedds_cpp",
        ] {
            assert_eq!(redact_secrets(s), s);
        }
    }

    #[test]
    fn json_strings_are_redacted_everywhere() {
        let mut v = serde_json::json!({
            "effective": {"vars": {"CYCLONEDDS_URI": "<Password>pw1</Password>"}},
            "shell": {"lines": [{"value": "'pin-value=99'"}]},
            "n": 3
        });
        redact_json(&mut v);
        let s = v.to_string();
        assert!(!s.contains("pw1") && !s.contains("99'"), "{s}");
        assert_eq!(v["n"], 3);
    }
}
