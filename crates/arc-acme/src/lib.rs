#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::StreamExt;
use hkdf::Hkdf;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use rustls_acme::rustls::{self, pki_types::pem::PemObject, pki_types::CertificateDer};
use rustls_acme::{
    AccountCache, AcmeConfig, AcmeState, CertCache, EventOk, ResolvesServerCertAcme, UseChallenge,
};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    runtime::Builder as TokioRuntimeBuilder,
    time,
};
use x509_parser::prelude::parse_x509_certificate;

const ENC_MAGIC: &[u8] = b"ARACME1";
const ENC_NONCE_LEN: usize = 12;

/// ACME challenge type supported by `rustls-acme`:
/// - TLS-ALPN-01 (recommended when you only serve HTTPS and want everything on :443)
/// - HTTP-01 (requires a dedicated HTTP listener, typically :80)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeType {
    TlsAlpn01,
    Http01,
}

impl ChallengeType {
    fn to_use_challenge(self) -> UseChallenge {
        match self {
            ChallengeType::TlsAlpn01 => UseChallenge::TlsAlpn01,
            ChallengeType::Http01 => UseChallenge::Http01,
        }
    }
}

/// Runtime config for ACME service.
#[derive(Clone, Debug)]
pub struct AcmeRuntimeConfig {
    /// Contact email (without `mailto:` prefix; we will add it).
    pub email: String,

    pub domains: Vec<String>,

    /// Encrypt-at-rest cache directory. This directory contains encrypted account and cert blobs.
    pub cache_dir: PathBuf,

    pub master_key: String,

    /// If `true`, use Let's Encrypt staging; else production.
    pub staging: bool,

    /// Optional override for directory URL (custom ACME CA). If set, it wins over `staging`.
    pub directory_url: Option<String>,

    /// Optional PEM bundle for ACME directory TLS trust roots.
    /// When set, rustls-acme client uses this trust store instead of webpki roots.
    pub directory_ca_pem: Option<Vec<u8>>,

    /// Preferred challenge type.
    pub challenge: ChallengeType,

    /// Optional dedicated HTTP-01 listener. If `challenge == Http01`, this MUST be set.
    ///
    /// This server only serves `/.well-known/acme-challenge/<token>` and returns 404 otherwise.
    pub http01_listen: Option<SocketAddr>,

    /// Max startup jitter to spread initial issuance load.
    pub startup_jitter_max: Duration,

    /// Tokio runtime worker threads for ACME background tasks.
    pub runtime_threads: usize,
}

impl Default for AcmeRuntimeConfig {
    fn default() -> Self {
        Self {
            email: String::new(),
            domains: Vec::new(),
            cache_dir: PathBuf::from("./arc_acme_cache"),
            master_key: String::new(),
            staging: true,
            directory_url: None,
            directory_ca_pem: None,
            challenge: ChallengeType::TlsAlpn01,
            http01_listen: None,
            startup_jitter_max: Duration::from_secs(30 * 60),
            runtime_threads: 2,
        }
    }
}

#[derive(Debug)]
pub enum AcmeError {
    Config(String),
    Io(String, std::io::Error),
    Join(String),
    Crypto(String),
    Pem(String),
    X509(String),
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcmeError::Config(s) => write!(f, "config error: {s}"),
            AcmeError::Io(ctx, e) => write!(f, "io error ({ctx}): {e}"),
            AcmeError::Join(ctx) => write!(f, "join error ({ctx})"),
            AcmeError::Crypto(s) => write!(f, "crypto error: {s}"),
            AcmeError::Pem(s) => write!(f, "pem parse error: {s}"),
            AcmeError::X509(s) => write!(f, "x509 parse error: {s}"),
        }
    }
}

impl std::error::Error for AcmeError {}

fn normalize_domain(s: &str) -> Result<String, AcmeError> {
    let d = s.trim().to_ascii_lowercase();
    if d.is_empty() {
        return Err(AcmeError::Config("domain is empty".into()));
    }
    if d.contains('*') {
        return Err(AcmeError::Config(format!(
            "wildcard domain is not supported by rustls-acme HTTP-01/TLS-ALPN-01: {d}"
        )));
    }
    Ok(d)
}

fn normalize_host_header(host: &str) -> String {
    let h = host.trim();
    let h = h.strip_suffix('.').unwrap_or(h);
    if let Some((h2, _port)) = h.rsplit_once(':') {
        // best-effort: if it's ipv6 bracketed or contains other colons, keep original
        if h2.contains(']') || h2.contains(':') {
            return h.to_ascii_lowercase();
        }
        return h2.to_ascii_lowercase();
    }
    h.to_ascii_lowercase()
}

fn jitter_duration(key: &str, max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::from_secs(0);
    }
    let max_ms = max.as_millis();
    if max_ms == 0 {
        return Duration::from_secs(0);
    }
    let hk = Hkdf::<Sha256>::new(Some(b"arc-acme-jitter-v1"), key.as_bytes());
    let mut out = [0u8; 8];
    // hkdf expand cannot fail for fixed length.
    hk.expand(b"ms", &mut out).ok();
    let n = u64::from_be_bytes(out);
    let jitter_ms = (n % (max_ms as u64)) as u64;
    Duration::from_millis(jitter_ms)
}

fn parse_master_key_material(s: &str) -> Result<Vec<u8>, AcmeError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("base64:") {
        return BASE64_STANDARD
            .decode(rest.trim())
            .map_err(|e| AcmeError::Config(format!("invalid base64 master_key: {e}")));
    }
    if let Some(rest) = s.strip_prefix("hex:") {
        return hex_decode(rest.trim());
    }
    Ok(s.as_bytes().to_vec())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, AcmeError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(AcmeError::Config(
            "invalid hex master_key: odd length".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => return Err(AcmeError::Config("invalid hex master_key".into())),
        }
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn hash_key(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(p.as_ref());
        h.update([0u8]);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

struct CryptoContext {
    rng: SystemRandom,
    cert_key: LessSafeKey,
    account_key: LessSafeKey,
}

impl CryptoContext {
    fn new(master_key: &str) -> Result<Self, AcmeError> {
        let mk = parse_master_key_material(master_key)?;
        if mk.len() < 32 {
            return Err(AcmeError::Config(
                "master_key material too short; require >= 32 bytes (after decoding)".into(),
            ));
        }

        let hk = Hkdf::<Sha256>::new(Some(b"arc-acme-kdf-v1"), &mk);

        let mut cert_key_bytes = [0u8; 32];
        hk.expand(b"cert-aead-key", &mut cert_key_bytes)
            .map_err(|_| AcmeError::Crypto("hkdf expand failed for cert key".into()))?;

        let mut acct_key_bytes = [0u8; 32];
        hk.expand(b"account-aead-key", &mut acct_key_bytes)
            .map_err(|_| AcmeError::Crypto("hkdf expand failed for account key".into()))?;

        let cert_key = LessSafeKey::new(
            UnboundKey::new(&aead::CHACHA20_POLY1305, &cert_key_bytes)
                .map_err(|_| AcmeError::Crypto("invalid cert AEAD key".into()))?,
        );
        let account_key = LessSafeKey::new(
            UnboundKey::new(&aead::CHACHA20_POLY1305, &acct_key_bytes)
                .map_err(|_| AcmeError::Crypto("invalid account AEAD key".into()))?,
        );

        Ok(Self {
            rng: SystemRandom::new(),
            cert_key,
            account_key,
        })
    }

    fn seal(&self, key: &LessSafeKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AcmeError> {
        let mut nonce_bytes = [0u8; ENC_NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| AcmeError::Crypto("failed to generate nonce".into()))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        in_out.extend_from_slice(&vec![0u8; aead::CHACHA20_POLY1305.tag_len()]);

        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| AcmeError::Crypto("AEAD seal failed".into()))?;

        let mut out = Vec::with_capacity(ENC_MAGIC.len() + ENC_NONCE_LEN + in_out.len());
        out.extend_from_slice(ENC_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    fn open(&self, key: &LessSafeKey, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AcmeError> {
        if ciphertext.len() < ENC_MAGIC.len() + ENC_NONCE_LEN + aead::CHACHA20_POLY1305.tag_len() {
            return Err(AcmeError::Crypto("ciphertext too short".into()));
        }
        if &ciphertext[..ENC_MAGIC.len()] != ENC_MAGIC {
            return Err(AcmeError::Crypto("bad magic header".into()));
        }
        let nonce_start = ENC_MAGIC.len();
        let nonce_end = nonce_start + ENC_NONCE_LEN;

        let mut nonce_bytes = [0u8; ENC_NONCE_LEN];
        nonce_bytes.copy_from_slice(&ciphertext[nonce_start..nonce_end]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext[nonce_end..].to_vec();
        let plain = key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| AcmeError::Crypto("AEAD open failed".into()))?;
        Ok(plain.to_vec())
    }
}

#[derive(Clone, Debug)]
pub enum DomainState {
    Starting,
    Ready,
    Error,
}

#[derive(Clone, Debug)]
pub struct DomainStatus {
    pub domain: String,
    pub state: DomainState,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub last_event: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub consecutive_failures: u32,
}

impl DomainStatus {
    fn new(domain: String) -> Self {
        Self {
            domain,
            state: DomainState::Starting,
            not_before: None,
            not_after: None,
            last_event: None,
            last_error: None,
            updated_at: Utc::now(),
            consecutive_failures: 0,
        }
    }
}

struct RoutingTable {
    exact: HashMap<String, Arc<ResolvesServerCertAcme>>,
}

impl RoutingTable {
    fn empty() -> Self {
        Self {
            exact: HashMap::new(),
        }
    }

    fn get(&self, domain: &str) -> Option<Arc<ResolvesServerCertAcme>> {
        self.exact.get(domain).cloned()
    }
}

struct DomainRunner {
    domain: String,
    state: AcmeState<CacheError, CacheError>,
    startup_delay: Duration,
}

#[derive(Clone, Debug)]
pub struct CacheError {
    pub msg: String,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{msg}", msg = self.msg)
    }
}

impl std::error::Error for CacheError {}

fn cache_err(msg: impl Into<String>) -> CacheError {
    CacheError { msg: msg.into() }
}

async fn read_optional_file(path: PathBuf) -> Result<Option<Vec<u8>>, CacheError> {
    let display = path.display().to_string();
    let res = tokio::task::spawn_blocking(move || std::fs::read(&path)).await;
    match res {
        Err(_) => Err(cache_err(format!("join error reading {display}"))),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(Err(e)) => Err(cache_err(format!("io error reading {display}: {e}"))),
        Ok(Ok(bytes)) => Ok(Some(bytes)),
    }
}

async fn atomic_write_file(path: PathBuf, data: Vec<u8>) -> Result<(), CacheError> {
    let display = path.display().to_string();
    let res = tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp = path.clone();
        let mut suffix = [0u8; 8];
        SystemRandom::new().fill(&mut suffix).ok();
        let suffix_hex = to_hex(&suffix);
        tmp.set_extension(format!("tmp.{suffix_hex}"));

        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent() {
            let dir = std::fs::File::open(parent)?;
            dir.sync_all()?;
        }
        Ok(())
    })
    .await;

    match res {
        Err(_) => Err(cache_err(format!("join error writing {display}"))),
        Ok(Err(e)) => Err(cache_err(format!("io error writing {display}: {e}"))),
        Ok(Ok(())) => Ok(()),
    }
}

fn parse_cert_validity(pem_bytes: &[u8]) -> Result<(DateTime<Utc>, DateTime<Utc>), AcmeError> {
    let pems = pem::parse_many(pem_bytes).map_err(|e| AcmeError::Pem(format!("{e}")))?;
    if pems.len() < 2 {
        return Err(AcmeError::Pem(format!(
            "expected >=2 PEM blocks (key + cert chain), got {}",
            pems.len()
        )));
    }

    // pems[0] is private key, pems[1] is leaf certificate
    let cert_der = pems[1].contents();
    let (_rem, cert) =
        parse_x509_certificate(&cert_der).map_err(|e| AcmeError::X509(format!("{e}")))?;
    let nb_dt = cert.validity().not_before.to_datetime();
    let na_dt = cert.validity().not_after.to_datetime();
    let nb = DateTime::<Utc>::from_timestamp(nb_dt.unix_timestamp(), nb_dt.nanosecond())
        .ok_or_else(|| AcmeError::X509("invalid not_before timestamp".into()))?;
    let na = DateTime::<Utc>::from_timestamp(na_dt.unix_timestamp(), na_dt.nanosecond())
        .ok_or_else(|| AcmeError::X509("invalid not_after timestamp".into()))?;
    Ok((nb, na))
}

fn build_directory_client_config(
    cfg: &AcmeRuntimeConfig,
) -> Result<Option<Arc<rustls::ClientConfig>>, AcmeError> {
    let Some(ca_pem) = cfg.directory_ca_pem.as_ref() else {
        return Ok(None);
    };

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ca_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AcmeError::Config(format!("invalid directory_ca_pem: {e}")))?;
    if certs.is_empty() {
        return Err(AcmeError::Config(
            "directory_ca_pem does not contain any certificate".into(),
        ));
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| AcmeError::Config(format!("directory_ca_pem add cert failed: {e}")))?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| AcmeError::Config(format!("acme client tls protocol config failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Some(Arc::new(client_config)))
}

#[derive(Clone)]
struct EncryptedCertCache {
    root: PathBuf,
    crypto: Arc<CryptoContext>,
    service: Weak<AcmeService>,
}

impl EncryptedCertCache {
    fn path_for(&self, domains: &[String], directory_url: &str) -> PathBuf {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(1 + domains.len());
        parts.push(directory_url.as_bytes().to_vec());
        for d in domains {
            parts.push(d.as_bytes().to_vec());
        }
        let key = hash_key(parts.iter().map(|v| v.as_slice()));
        let name = to_hex(&key);
        self.root.join("certs").join(format!("{name}.bin"))
    }

    fn aad_for(&self, domains: &[String], directory_url: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"arc-acme-cert-aad-v1\0");
        aad.extend_from_slice(directory_url.as_bytes());
        aad.push(0);
        for d in domains {
            aad.extend_from_slice(d.as_bytes());
            aad.push(0);
        }
        aad
    }
}

#[async_trait]
impl CertCache for EncryptedCertCache {
    type EC = CacheError;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let path = self.path_for(domains, directory_url);
        let Some(cipher) = read_optional_file(path).await? else {
            return Ok(None);
        };

        let aad = self.aad_for(domains, directory_url);
        let plain = self
            .crypto
            .open(&self.crypto.cert_key, &aad, &cipher)
            .map_err(|e| cache_err(format!("decrypt cert failed: {e}")))?;

        if let Ok((nb, na)) = parse_cert_validity(&plain) {
            if let Some(service) = self.service.upgrade() {
                for d in domains {
                    service.update_validity(d, Some(nb), Some(na));
                    service.set_state(
                        d,
                        DomainState::Ready,
                        Some("DeployedCachedCert".into()),
                        None,
                    );
                }
            }
        }

        Ok(Some(plain))
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let path = self.path_for(domains, directory_url);
        let aad = self.aad_for(domains, directory_url);

        let cipher = self
            .crypto
            .seal(&self.crypto.cert_key, &aad, cert)
            .map_err(|e| cache_err(format!("encrypt cert failed: {e}")))?;

        atomic_write_file(path, cipher).await?;

        if let Ok((nb, na)) = parse_cert_validity(cert) {
            if let Some(service) = self.service.upgrade() {
                for d in domains {
                    service.update_validity(d, Some(nb), Some(na));
                    service.set_state(d, DomainState::Ready, Some("DeployedNewCert".into()), None);
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
struct EncryptedAccountCache {
    root: PathBuf,
    crypto: Arc<CryptoContext>,
}

impl EncryptedAccountCache {
    fn path_for(&self, contact: &[String], directory_url: &str) -> PathBuf {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(1 + contact.len());
        parts.push(directory_url.as_bytes().to_vec());
        for c in contact {
            parts.push(c.as_bytes().to_vec());
        }
        let key = hash_key(parts.iter().map(|v| v.as_slice()));
        let name = to_hex(&key);
        self.root.join("accounts").join(format!("{name}.bin"))
    }

    fn aad_for(&self, contact: &[String], directory_url: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"arc-acme-account-aad-v1\0");
        aad.extend_from_slice(directory_url.as_bytes());
        aad.push(0);
        for c in contact {
            aad.extend_from_slice(c.as_bytes());
            aad.push(0);
        }
        aad
    }
}

#[async_trait]
impl AccountCache for EncryptedAccountCache {
    type EA = CacheError;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let path = self.path_for(contact, directory_url);
        let Some(cipher) = read_optional_file(path).await? else {
            return Ok(None);
        };

        let aad = self.aad_for(contact, directory_url);
        let plain = self
            .crypto
            .open(&self.crypto.account_key, &aad, &cipher)
            .map_err(|e| cache_err(format!("decrypt account failed: {e}")))?;

        Ok(Some(plain))
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let path = self.path_for(contact, directory_url);
        let aad = self.aad_for(contact, directory_url);

        let cipher = self
            .crypto
            .seal(&self.crypto.account_key, &aad, account)
            .map_err(|e| cache_err(format!("encrypt account failed: {e}")))?;

        atomic_write_file(path, cipher).await?;
        Ok(())
    }
}

pub struct AcmeService {
    cfg: AcmeRuntimeConfig,
    routing: ArcSwap<RoutingTable>,
    status: DashMap<String, DomainStatus>,
}

impl AcmeService {
    pub fn start_threaded(cfg: AcmeRuntimeConfig) -> Result<Arc<Self>, AcmeError> {
        let cfg = Self::validate_and_normalize(cfg)?;

        if cfg.challenge == ChallengeType::Http01 && cfg.http01_listen.is_none() {
            return Err(AcmeError::Config(
                "challenge=http-01 requires http01_listen".into(),
            ));
        }

        // Pre-flight: ensure cache dir exists and is writable.
        std::fs::create_dir_all(&cfg.cache_dir).map_err(|e| {
            AcmeError::Io(format!("create cache_dir {}", cfg.cache_dir.display()), e)
        })?;

        // Pre-flight: if HTTP-01 listener enabled, check port availability early.
        if let Some(bind) = cfg.http01_listen {
            // best-effort: bind + drop immediately
            std::net::TcpListener::bind(bind)
                .map_err(|e| AcmeError::Io(format!("bind http01_listen {bind}"), e))?;
        }

        let crypto = Arc::new(CryptoContext::new(&cfg.master_key)?);

        let svc = Arc::new(Self {
            cfg: cfg.clone(),
            routing: ArcSwap::from_pointee(RoutingTable::empty()),
            status: DashMap::new(),
        });

        let mut routing = HashMap::<String, Arc<ResolvesServerCertAcme>>::new();
        let mut runners: Vec<DomainRunner> = Vec::new();

        let weak = Arc::downgrade(&svc);

        let contact = format!("mailto:{}", cfg.email);

        for domain in &cfg.domains {
            // initialize status
            svc.status
                .insert(domain.clone(), DomainStatus::new(domain.clone()));

            let domains_for_state = vec![domain.clone()];

            let cert_cache = EncryptedCertCache {
                root: cfg.cache_dir.clone(),
                crypto: crypto.clone(),
                service: weak.clone(),
            };
            let account_cache = EncryptedAccountCache {
                root: cfg.cache_dir.clone(),
                crypto: crypto.clone(),
            };

            let mut acme_cfg = if let Some(client_cfg) = build_directory_client_config(&cfg)? {
                AcmeConfig::new_with_client_config(domains_for_state.clone(), client_cfg)
            } else {
                AcmeConfig::new(domains_for_state.clone())
            }
            .directory_lets_encrypt(!cfg.staging)
            .contact_push(contact.as_str())
            .challenge_type(cfg.challenge.to_use_challenge())
            .cache_compose(cert_cache, account_cache);

            if let Some(ref url) = cfg.directory_url {
                acme_cfg = acme_cfg.directory(url.as_str());
            }

            let state = acme_cfg.state();
            let resolver = state.resolver();

            routing.insert(domain.clone(), resolver);

            let startup_delay = jitter_duration(domain, cfg.startup_jitter_max);

            runners.push(DomainRunner {
                domain: domain.clone(),
                state,
                startup_delay,
            });
        }

        svc.routing.store(Arc::new(RoutingTable { exact: routing }));

        // Spawn background runtime thread
        let svc_run = svc.clone();
        std::thread::Builder::new()
            .name("arc-acme".to_string())
            .spawn(move || {
                let rt = match TokioRuntimeBuilder::new_multi_thread()
                    .worker_threads(svc_run.cfg.runtime_threads.max(1))
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("[arc-acme] failed to build tokio runtime: {e}");
                        return;
                    }
                };

                rt.block_on(async move {
                    // optional HTTP-01 server
                    if let Some(bind) = svc_run.cfg.http01_listen {
                        let svc_http = svc_run.clone();
                        tokio::spawn(async move {
                            if let Err(e) = run_http01_server(bind, svc_http).await {
                                eprintln!("[arc-acme] http01 server error: {e}");
                            }
                        });
                    }

                    // domain runners
                    for mut runner in runners {
                        let svc_domain = svc_run.clone();
                        tokio::spawn(async move {
                            if !runner.startup_delay.is_zero() {
                                time::sleep(runner.startup_delay).await;
                            }
                            svc_domain.set_state(
                                &runner.domain,
                                DomainState::Starting,
                                Some("RunnerStarted".into()),
                                None,
                            );

                            loop {
                                match runner.state.next().await {
                                    Some(Ok(ok)) => {
                                        svc_domain.on_event_ok(&runner.domain, ok);
                                    }
                                    Some(Err(err)) => {
                                        svc_domain.on_event_err(&runner.domain, &err);
                                    }
                                    None => {
                                        svc_domain.set_state(
                                            &runner.domain,
                                            DomainState::Error,
                                            Some("RunnerEnded".into()),
                                            Some("acme state stream ended".into()),
                                        );
                                        break;
                                    }
                                }
                            }
                        });
                    }

                    futures::future::pending::<()>().await;
                });
            })
            .map_err(|e| AcmeError::Io("spawn arc-acme thread".into(), e))?;

        Ok(svc)
    }

    fn validate_and_normalize(mut cfg: AcmeRuntimeConfig) -> Result<AcmeRuntimeConfig, AcmeError> {
        if cfg.email.trim().is_empty() {
            return Err(AcmeError::Config("email is required".into()));
        }
        if cfg.domains.is_empty() {
            return Err(AcmeError::Config("domains is empty".into()));
        }

        let mut set = HashSet::<String>::new();
        let mut out = Vec::<String>::with_capacity(cfg.domains.len());
        for d in cfg.domains.drain(..) {
            let nd = normalize_domain(&d)?;
            if set.insert(nd.clone()) {
                out.push(nd);
            }
        }
        out.sort();
        cfg.domains = out;

        if cfg.runtime_threads == 0 {
            cfg.runtime_threads = 2;
        }

        Ok(cfg)
    }

    fn set_state(
        &self,
        domain: &str,
        state: DomainState,
        last_event: Option<String>,
        last_error: Option<String>,
    ) {
        if let Some(mut st) = self.status.get_mut(domain) {
            st.state = state;
            if let Some(ev) = last_event {
                st.last_event = Some(ev);
            }
            if let Some(err) = last_error {
                st.last_error = Some(err);
            }
            st.updated_at = Utc::now();
        }
    }

    fn update_validity(
        &self,
        domain: &str,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
    ) {
        if let Some(mut st) = self.status.get_mut(domain) {
            if not_before.is_some() {
                st.not_before = not_before;
            }
            if not_after.is_some() {
                st.not_after = not_after;
            }
            st.updated_at = Utc::now();
        }
    }

    fn on_event_ok(&self, domain: &str, ok: EventOk) {
        // We keep this intentionally tolerant to upstream enum changes.
        let ev = format!("{ok:?}");
        eprintln!("[arc-acme] domain={domain} event_ok={ev}");
        if let Some(mut st) = self.status.get_mut(domain) {
            st.last_event = Some(ev);
            st.last_error = None;
            st.consecutive_failures = 0;
            st.updated_at = Utc::now();
            // If a cert got deployed, caches already set Ready; keep Ready.
        }
    }

    fn on_event_err<E: fmt::Debug>(&self, domain: &str, err: &E) {
        let msg = format!("{err:?}");
        eprintln!("[arc-acme] domain={domain} event_err={msg}");
        if let Some(mut st) = self.status.get_mut(domain) {
            st.last_error = Some(msg);
            st.last_event = Some("Error".into());
            st.state = DomainState::Error;
            st.consecutive_failures = st.consecutive_failures.saturating_add(1);
            st.updated_at = Utc::now();
        }
    }

    /// For TLS (SNI) routing: return the per-domain `rustls-acme` resolver.
    /// The gateway composite resolver can delegate to this for ACME-managed domains.
    pub fn resolver_for_domain(&self, domain: &str) -> Option<Arc<ResolvesServerCertAcme>> {
        let d = domain.trim().to_ascii_lowercase();
        self.routing.load().get(&d)
    }

    /// For HTTP-01 response: returns the `keyAuthorization` string for a given (domain, token).
    pub fn http01_key_auth(&self, host: &str, token: &str) -> Option<String> {
        let host = normalize_host_header(host);
        let resolver = self.resolver_for_domain(&host)?;
        resolver.get_http_01_key_auth(token)
    }

    /// Snapshot of all domain statuses (cheap; clones).
    pub fn status_snapshot(&self) -> Vec<DomainStatus> {
        self.status.iter().map(|kv| kv.value().clone()).collect()
    }

    /// Whether TLS-ALPN-01 might be needed (i.e., service is enabled).
    pub fn is_running(&self) -> bool {
        true
    }
}

async fn run_http01_server(bind: SocketAddr, svc: Arc<AcmeService>) -> Result<(), AcmeError> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| AcmeError::Io(format!("http01 bind {bind}"), e))?;

    loop {
        let (mut stream, _peer) = listener
            .accept()
            .await
            .map_err(|e| AcmeError::Io("http01 accept".into(), e))?;

        let svc = svc.clone();
        tokio::spawn(async move {
            let _ = handle_http01_conn(&mut stream, svc).await;
        });
    }
}

async fn handle_http01_conn(
    stream: &mut tokio::net::TcpStream,
    svc: Arc<AcmeService>,
) -> Result<(), AcmeError> {
    // hard limit: read up to 8KB header, within 2s
    let mut buf = vec![0u8; 8192];
    let n = match time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(AcmeError::Io("http01 read".into(), e)),
        Err(_) => return Ok(()),
    };
    if n == 0 {
        return Ok(());
    }
    buf.truncate(n);

    let req = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        Err(_) => {
            write_http(stream, 400, "Bad Request", "invalid utf-8").await?;
            return Ok(());
        }
    };

    // parse request line
    let mut lines = req.split("\r\n");
    let Some(request_line) = lines.next() else {
        write_http(stream, 400, "Bad Request", "missing request line").await?;
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" && method != "HEAD" {
        write_http(stream, 405, "Method Not Allowed", "method not allowed").await?;
        return Ok(());
    }

    // parse headers
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                host = Some(v.trim().to_string());
            }
        }
    }

    let Some(host) = host else {
        write_http(stream, 400, "Bad Request", "missing host").await?;
        return Ok(());
    };

    const PREFIX: &str = "/.well-known/acme-challenge/";
    if !path.starts_with(PREFIX) {
        write_http(stream, 404, "Not Found", "not found").await?;
        return Ok(());
    }
    let token = &path[PREFIX.len()..];
    if token.is_empty() {
        write_http(stream, 404, "Not Found", "not found").await?;
        return Ok(());
    }

    if let Some(key_auth) = svc.http01_key_auth(&host, token) {
        // ACME expects plain text body.
        write_http(stream, 200, "OK", &key_auth).await?;
        return Ok(());
    }

    write_http(stream, 404, "Not Found", "not found").await?;
    Ok(())
}

async fn write_http(
    stream: &mut tokio::net::TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), AcmeError> {
    let body_bytes = body.as_bytes();
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body_bytes.len()
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| AcmeError::Io("http01 write headers".into(), e))?;
    stream
        .write_all(body_bytes)
        .await
        .map_err(|e| AcmeError::Io("http01 write body".into(), e))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/* -------------------------------------------------------------------------------------------------
Legacy API kept for compatibility with the earlier skeleton (deprecated).
------------------------------------------------------------------------------------------------- */

/// Simple interface to a lease/lock store for domain-level distributed locks.
#[deprecated(note = "Legacy API. Prefer AcmeService with external coordination if needed.")]
pub trait LeaseStore: Send + Sync {
    fn try_acquire(&self, key: &str, ttl_secs: u64) -> bool;
    fn release(&self, key: &str);
}

/// A certificate and private key.
#[deprecated(note = "Legacy API. Prefer AcmeService which uses rustls-acme resolvers directly.")]
pub struct AcmeCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub not_after_unix: u64,
}

/// An ACME provider interface.
#[deprecated(note = "Legacy API. Prefer AcmeService.")]
#[allow(deprecated)]
pub trait AcmeProvider: Send + Sync {
    fn obtain_or_renew(&self, domain: &str) -> Result<AcmeCert, String>;
}

/// ACME certificate manager (legacy).
#[deprecated(note = "Legacy API. Prefer AcmeService.")]
#[allow(deprecated)]
pub struct AcmeManager<P: AcmeProvider, L: LeaseStore> {
    acme: Arc<P>,
    lease: Arc<L>,
    domains: Vec<String>,
    // output paths for each domain, e.g. /etc/arc/certs/<domain>/cert.pem, key.pem
    output: HashMap<String, (PathBuf, PathBuf)>,
}

#[allow(deprecated)]
impl<P: AcmeProvider, L: LeaseStore> AcmeManager<P, L> {
    pub fn new(
        acme: Arc<P>,
        lease: Arc<L>,
        domains: Vec<String>,
        output: HashMap<String, (PathBuf, PathBuf)>,
    ) -> Self {
        Self {
            acme,
            lease,
            domains,
            output,
        }
    }

    pub fn tick(&self) {
        for d in &self.domains {
            let lock_key = format!("acme:{}", d);
            if !self.lease.try_acquire(&lock_key, 600) {
                continue;
            }
            let _ = (|| {
                let cert = self.acme.obtain_or_renew(d)?;
                if let Some((cert_path, key_path)) = self.output.get(d) {
                    Self::atomic_write(cert_path, &cert.cert_pem)
                        .map_err(|e| format!("write cert: {e}"))?;
                    Self::atomic_write(key_path, &cert.key_pem)
                        .map_err(|e| format!("write key: {e}"))?;
                }
                Ok::<(), String>(())
            })();
            self.lease.release(&lock_key);
        }
    }

    fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn normalize_domain_rejects_empty_or_wildcard_and_lowercases() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("   ").is_err());
        assert!(normalize_domain("*.example.com").is_err());
        assert_eq!(
            normalize_domain("API.Example.COM ").expect("normalize"),
            "api.example.com"
        );
    }

    #[test]
    fn normalize_host_header_strips_port_and_trailing_dot() {
        assert_eq!(normalize_host_header("EXAMPLE.com:443"), "example.com");
        assert_eq!(normalize_host_header("api.example.com."), "api.example.com");
        // IPv6 bracket case keeps original host-part behavior by design.
        assert_eq!(normalize_host_header("[::1]:443"), "[::1]:443");
    }

    #[test]
    fn jitter_duration_is_deterministic_and_bounded() {
        let max = Duration::from_secs(10);
        let a = jitter_duration("domain-a", max);
        let b = jitter_duration("domain-a", max);
        let c = jitter_duration("domain-b", max);
        assert_eq!(a, b);
        assert!(a <= max);
        assert!(c <= max);
    }

    #[test]
    fn parse_master_key_material_supports_plain_hex_base64() {
        let plain = parse_master_key_material("abc").expect("plain");
        assert_eq!(plain, b"abc");

        let hex = parse_master_key_material("hex:616263").expect("hex");
        assert_eq!(hex, b"abc");

        let b64 = parse_master_key_material("base64:YWJj").expect("base64");
        assert_eq!(b64, b"abc");

        assert!(parse_master_key_material("hex:6").is_err());
        assert!(parse_master_key_material("base64:@@@").is_err());
    }

    #[test]
    fn validate_and_normalize_sorts_dedups_and_fills_runtime_threads() {
        let cfg = AcmeRuntimeConfig {
            email: "ops@example.com".to_string(),
            domains: vec![
                "B.example.com".to_string(),
                "a.example.com".to_string(),
                "b.example.com".to_string(),
            ],
            runtime_threads: 0,
            ..AcmeRuntimeConfig::default()
        };
        let out = AcmeService::validate_and_normalize(cfg).expect("validate");
        assert_eq!(
            out.domains,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
        assert_eq!(out.runtime_threads, 2);
    }

    #[test]
    fn validate_and_normalize_requires_email_and_domains() {
        let no_email = AcmeRuntimeConfig {
            email: "".to_string(),
            domains: vec!["a.example.com".to_string()],
            ..AcmeRuntimeConfig::default()
        };
        assert!(AcmeService::validate_and_normalize(no_email).is_err());

        let no_domains = AcmeRuntimeConfig {
            email: "ops@example.com".to_string(),
            domains: Vec::new(),
            ..AcmeRuntimeConfig::default()
        };
        assert!(AcmeService::validate_and_normalize(no_domains).is_err());
    }

    fn make_empty_service() -> Arc<AcmeService> {
        Arc::new(AcmeService {
            cfg: AcmeRuntimeConfig::default(),
            routing: ArcSwap::from_pointee(RoutingTable::empty()),
            status: DashMap::new(),
        })
    }

    async fn run_http01_once(req: &[u8], svc: Arc<AcmeService>) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            handle_http01_conn(&mut stream, svc)
                .await
                .expect("handle conn");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client.write_all(req).await.expect("write request");
        let _ = client.shutdown().await;

        let mut out = Vec::new();
        client.read_to_end(&mut out).await.expect("read response");
        server.await.expect("join server");
        out
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http01_rejects_non_get_head_method() {
        let svc = make_empty_service();
        let resp = run_http01_once(
            b"POST /.well-known/acme-challenge/token HTTP/1.1\r\nHost: example.com\r\n\r\n",
            svc,
        )
        .await;
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 405 "));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http01_rejects_missing_host_header() {
        let svc = make_empty_service();
        let resp = run_http01_once(
            b"GET /.well-known/acme-challenge/token HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
            svc,
        )
        .await;
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 400 "));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http01_returns_404_for_non_challenge_path() {
        let svc = make_empty_service();
        let resp = run_http01_once(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n", svc).await;
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 404 "));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http01_returns_400_for_invalid_utf8_payload() {
        let svc = make_empty_service();
        let resp = run_http01_once(&[0xff, 0xfe, 0x00], svc).await;
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 400 "));
    }
}
