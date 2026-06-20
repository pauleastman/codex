use std::sync::Once;

const REQUIRED_SIGNATURE_SCHEME: rustls::SignatureScheme =
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512;

/// Ensures a process-wide rustls crypto provider is installed.
///
/// rustls cannot auto-select a provider when both `ring` and `aws-lc-rs`
/// features are enabled in the dependency graph.
pub fn ensure_rustls_crypto_provider() {
    static RUSTLS_PROVIDER_INIT: Once = Once::new();
    RUSTLS_PROVIDER_INIT.call_once(|| {
        // aws-lc-rs supports a broader WebPKI signature set than ring, including
        // ECDSA P-521/SHA-512 certs used by some enterprise TLS proxies.
        if default_provider().install_default().is_err() {
            // Preserve the previous best-effort behavior for embedded hosts that
            // install a process-global provider before Codex can install one.
            return;
        }

        let Some(provider) = rustls::crypto::CryptoProvider::get_default() else {
            panic!("rustls crypto provider should be installed");
        };
        if should_require_signature_scheme_support() {
            assert!(
                provider_supports_required_signature_scheme(provider),
                "installed rustls crypto provider must support {REQUIRED_SIGNATURE_SCHEME:?}"
            );
        }
    });
}

fn default_provider() -> rustls::crypto::CryptoProvider {
    if use_ring_provider() {
        // aws-lc-rs 1.16.x can trap during provider initialization on some
        // Intel Macs. Keep the pre-0.141 provider on that target.
        rustls::crypto::ring::default_provider()
    } else {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

fn use_ring_provider() -> bool {
    cfg!(all(target_os = "macos", target_arch = "x86_64"))
}

fn should_require_signature_scheme_support() -> bool {
    !use_ring_provider()
}

fn provider_supports_required_signature_scheme(provider: &rustls::crypto::CryptoProvider) -> bool {
    provider
        .signature_verification_algorithms
        .supported_schemes()
        .contains(&REQUIRED_SIGNATURE_SCHEME)
}
