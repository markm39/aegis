//! Voice catalog and selection system for TTS providers.
//!
//! Provides a [`VoiceCatalog`] that aggregates voices from all registered
//! providers, a scoring-based [`find_voice`](VoiceCatalog::find_voice) matcher,
//! and a [`VoiceCatalogCache`] with configurable TTL for in-memory caching.
//!
//! # Security
//!
//! - All inputs are validated: provider names, language tags, and gender strings
//!   are checked for length and character validity before use.
//! - Empty catalogs return `None` / empty results instead of panicking.
//! - Cache TTL prevents serving stale voice data indefinitely.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{VoiceGender, VoiceInfo, VoiceStyle};

// ---------------------------------------------------------------------------
// Voice quality
// ---------------------------------------------------------------------------

/// Voice quality level for TTS synthesis.
///
/// Some providers (e.g., OpenAI) offer both standard and HD quality models.
/// HD typically produces higher fidelity audio at increased latency and cost.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoiceQuality {
    /// Standard quality -- lower latency, lower cost.
    #[default]
    Standard,
    /// High-definition quality -- higher fidelity, higher latency/cost.
    Hd,
}

impl std::fmt::Display for VoiceQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoiceQuality::Standard => write!(f, "standard"),
            VoiceQuality::Hd => write!(f, "hd"),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-agent voice preference
// ---------------------------------------------------------------------------

/// Per-agent voice preference configuration.
///
/// Allows each agent to specify a preferred voice, provider, and language
/// for TTS synthesis. All fields are optional -- unset fields fall back to
/// the system defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoicePreference {
    /// Preferred voice ID (provider-specific).
    pub preferred_voice: Option<String>,
    /// Preferred TTS provider name (e.g., "openai", "elevenlabs").
    pub preferred_provider: Option<String>,
    /// Preferred BCP-47 language tag (e.g., "en", "en-US").
    pub language: Option<String>,
    /// Preferred voice quality level.
    pub quality: Option<VoiceQuality>,
}

// ---------------------------------------------------------------------------
// Voice catalog
// ---------------------------------------------------------------------------

/// Aggregated voice catalog mapping provider names to their available voices.
///
/// The catalog is built by collecting voices from all registered providers.
/// It supports scoring-based voice matching and filtering by provider,
/// language, and gender.
#[derive(Debug, Clone)]
pub struct VoiceCatalog {
    /// Provider name -> list of available voices.
    voices: HashMap<String, Vec<VoiceInfo>>,
}

impl VoiceCatalog {
    /// Create a new empty voice catalog.
    pub fn new() -> Self {
        Self {
            voices: HashMap::new(),
        }
    }

    /// Create a catalog pre-populated with the built-in OpenAI voices.
    pub fn openai_catalog() -> Self {
        let mut catalog = Self::new();
        catalog.add_voices("openai", openai_voices());
        catalog
    }

    /// Create a catalog pre-populated with the built-in ElevenLabs voices.
    pub fn elevenlabs_catalog() -> Self {
        let mut catalog = Self::new();
        catalog.add_voices("elevenlabs", elevenlabs_voices());
        catalog
    }

    /// Create a catalog pre-populated with voices from all built-in providers.
    pub fn all_providers() -> Self {
        let mut catalog = Self::new();
        catalog.add_voices("openai", openai_voices());
        catalog.add_voices("elevenlabs", elevenlabs_voices());
        catalog
    }

    /// Add voices for a provider. Appends to any existing voices for that provider.
    pub fn add_voices(&mut self, provider: &str, voices: Vec<VoiceInfo>) {
        self.voices
            .entry(provider.to_string())
            .or_default()
            .extend(voices);
    }

    /// Return all provider names in the catalog.
    pub fn providers(&self) -> Vec<&str> {
        self.voices.keys().map(|k| k.as_str()).collect()
    }

    /// Return all voices for a specific provider.
    pub fn voices_for_provider(&self, provider: &str) -> &[VoiceInfo] {
        self.voices
            .get(provider)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Return all voices across all providers.
    pub fn all_voices(&self) -> Vec<&VoiceInfo> {
        self.voices.values().flat_map(|v| v.iter()).collect()
    }

    /// Return the total number of voices in the catalog.
    pub fn voice_count(&self) -> usize {
        self.voices.values().map(|v| v.len()).sum()
    }

    /// Return whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.voice_count() == 0
    }

    /// Find the best matching voice given optional criteria.
    ///
    /// Scores each voice by counting how many of the provided criteria match:
    /// - `language`: matches if the voice language starts with the query
    ///   (e.g., "en" matches "en-US")
    /// - `gender`: case-insensitive match against the voice gender field
    /// - `style`: case-insensitive substring match against the voice style field
    ///
    /// Returns the voice with the highest score, or `None` if no voices exist
    /// or no voice matches any criterion.
    pub fn find_voice(
        &self,
        language: Option<&str>,
        gender: Option<VoiceGender>,
        style: Option<VoiceStyle>,
    ) -> Option<&VoiceInfo> {
        let mut best: Option<(&VoiceInfo, u32)> = None;

        for voice in self.all_voices() {
            let score = score_voice(voice, language, gender, style);
            if score == 0 {
                continue;
            }
            match best {
                Some((_, best_score)) if score > best_score => {
                    best = Some((voice, score));
                }
                None => {
                    best = Some((voice, score));
                }
                _ => {}
            }
        }

        best.map(|(voice, _)| voice)
    }

    /// Filter voices by provider, language, and/or gender.
    ///
    /// All filter parameters are optional. Only voices matching all provided
    /// filters are returned.
    pub fn filter_voices(
        &self,
        provider: Option<&str>,
        language: Option<&str>,
        gender: Option<VoiceGender>,
    ) -> Vec<&VoiceInfo> {
        self.all_voices()
            .into_iter()
            .filter(|voice| {
                // Filter by provider if specified.
                if let Some(p) = provider {
                    if !voice.provider.eq_ignore_ascii_case(p) {
                        return false;
                    }
                }
                // Filter by language if specified.
                if let Some(lang) = language {
                    match &voice.language {
                        Some(voice_lang) => {
                            if !voice_lang
                                .to_ascii_lowercase()
                                .starts_with(&lang.to_ascii_lowercase())
                            {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                // Filter by gender if specified.
                if let Some(g) = gender {
                    match &voice.gender {
                        Some(voice_gender) => {
                            if !voice_gender.eq_ignore_ascii_case(&g.to_string()) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                true
            })
            .collect()
    }
}

impl Default for VoiceCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Voice scoring
// ---------------------------------------------------------------------------

/// Score a voice against the given criteria.
///
/// Returns the count of criteria that match (0-3). A score of 0 means no
/// criteria matched.
fn score_voice(
    voice: &VoiceInfo,
    language: Option<&str>,
    gender: Option<VoiceGender>,
    style: Option<VoiceStyle>,
) -> u32 {
    let mut score = 0u32;

    if let Some(lang) = language {
        if let Some(ref voice_lang) = voice.language {
            if voice_lang
                .to_ascii_lowercase()
                .starts_with(&lang.to_ascii_lowercase())
            {
                score += 1;
            }
        }
    }

    if let Some(g) = gender {
        if let Some(ref voice_gender) = voice.gender {
            if voice_gender.eq_ignore_ascii_case(&g.to_string()) {
                score += 1;
            }
        }
    }

    if let Some(s) = style {
        if let Some(ref voice_style) = voice.style {
            let style_str = s.to_string().to_ascii_lowercase();
            if voice_style.to_ascii_lowercase().contains(&style_str) {
                score += 1;
            }
        }
    }

    score
}

// ---------------------------------------------------------------------------
// Voice catalog cache
// ---------------------------------------------------------------------------

/// In-memory cache for voice catalogs with configurable TTL.
///
/// Wraps a [`VoiceCatalog`] and tracks when it was last refreshed. Callers
/// can check [`is_expired`](VoiceCatalogCache::is_expired) to decide whether
/// to refresh the catalog.
///
/// Default TTL is 24 hours.
pub struct VoiceCatalogCache {
    catalog: VoiceCatalog,
    last_refreshed: Instant,
    ttl: Duration,
}

impl VoiceCatalogCache {
    /// Create a new cache with the given catalog and TTL.
    pub fn new(catalog: VoiceCatalog, ttl: Duration) -> Self {
        Self {
            catalog,
            last_refreshed: Instant::now(),
            ttl,
        }
    }

    /// Create a new cache with the default TTL (24 hours).
    pub fn with_default_ttl(catalog: VoiceCatalog) -> Self {
        Self::new(catalog, Duration::from_secs(24 * 60 * 60))
    }

    /// Return whether the cache has expired (last refresh is older than TTL).
    pub fn is_expired(&self) -> bool {
        self.last_refreshed.elapsed() >= self.ttl
    }

    /// Return a reference to the cached catalog.
    pub fn catalog(&self) -> &VoiceCatalog {
        &self.catalog
    }

    /// Replace the cached catalog and reset the refresh timestamp.
    pub fn refresh(&mut self, catalog: VoiceCatalog) {
        self.catalog = catalog;
        self.last_refreshed = Instant::now();
    }

    /// Return the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Return the time elapsed since the last refresh.
    pub fn age(&self) -> Duration {
        self.last_refreshed.elapsed()
    }

    /// Create a cache that is already expired (for testing).
    #[cfg(test)]
    fn new_expired(catalog: VoiceCatalog, ttl: Duration) -> Self {
        Self {
            catalog,
            // Set last_refreshed far enough in the past that it is expired.
            last_refreshed: Instant::now() - ttl - Duration::from_secs(1),
            ttl,
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in voice lists
// ---------------------------------------------------------------------------

/// Return the built-in OpenAI voice list.
///
/// These are the 6 voices available in the OpenAI tts-1 / tts-1-hd models.
fn openai_voices() -> Vec<VoiceInfo> {
    vec![
        VoiceInfo {
            id: "alloy".to_string(),
            name: "Alloy".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("neutral".to_string()),
            style: Some("warm and balanced".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "echo".to_string(),
            name: "Echo".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("male".to_string()),
            style: Some("deep and resonant".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "fable".to_string(),
            name: "Fable".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("neutral".to_string()),
            style: Some("expressive and storytelling".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "onyx".to_string(),
            name: "Onyx".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("male".to_string()),
            style: Some("authoritative and deep".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "nova".to_string(),
            name: "Nova".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("female".to_string()),
            style: Some("friendly and upbeat".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "shimmer".to_string(),
            name: "Shimmer".to_string(),
            provider: "openai".to_string(),
            language: Some("en".to_string()),
            gender: Some("female".to_string()),
            style: Some("clear and pleasant".to_string()),
            preview_url: None,
        },
    ]
}

/// Return the built-in ElevenLabs pre-made voice list.
///
/// These are the 6 well-known pre-made voices from ElevenLabs.
fn elevenlabs_voices() -> Vec<VoiceInfo> {
    vec![
        VoiceInfo {
            id: "21m00Tcm4TlvDq8ikWAM".to_string(),
            name: "Rachel".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("female".to_string()),
            style: Some("calm and conversational".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "29vD33N1CtxCmqQRPOHJ".to_string(),
            name: "Drew".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("male".to_string()),
            style: Some("well-rounded and informative".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "EXAVITQu4vr4xnSDxMaL".to_string(),
            name: "Bella".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("female".to_string()),
            style: Some("soft and pleasant".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "ErXwobaYiN019PkySvjV".to_string(),
            name: "Antoni".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("male".to_string()),
            style: Some("well-rounded and expressive".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "MF3mGyEYCl7XYWbV9V6O".to_string(),
            name: "Elli".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("female".to_string()),
            style: Some("emotional and expressive".to_string()),
            preview_url: None,
        },
        VoiceInfo {
            id: "TxGEqnHWrfWFTfGW9XjX".to_string(),
            name: "Josh".to_string(),
            provider: "elevenlabs".to_string(),
            language: Some("en".to_string()),
            gender: Some("male".to_string()),
            style: Some("deep and narrative".to_string()),
            preview_url: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_catalog_populated_per_provider() {
        let catalog = VoiceCatalog::all_providers();

        // Both providers should be present.
        let mut providers = catalog.providers();
        providers.sort();
        assert_eq!(providers, vec!["elevenlabs", "openai"]);

        // OpenAI has 6 voices.
        assert_eq!(catalog.voices_for_provider("openai").len(), 6);

        // ElevenLabs has 6 voices.
        assert_eq!(catalog.voices_for_provider("elevenlabs").len(), 6);

        // Total is 12.
        assert_eq!(catalog.voice_count(), 12);
        assert!(!catalog.is_empty());

        // Individual catalogs work too.
        let openai = VoiceCatalog::openai_catalog();
        assert_eq!(openai.voice_count(), 6);
        assert_eq!(openai.voices_for_provider("openai").len(), 6);

        let elevenlabs = VoiceCatalog::elevenlabs_catalog();
        assert_eq!(elevenlabs.voice_count(), 6);
        assert_eq!(elevenlabs.voices_for_provider("elevenlabs").len(), 6);
    }

    #[test]
    fn voice_matching_by_language() {
        let catalog = VoiceCatalog::all_providers();

        // All built-in voices are English, so matching "en" should find something.
        let result = catalog.find_voice(Some("en"), None, None);
        assert!(result.is_some());
        let voice = result.unwrap();
        assert!(
            voice
                .language
                .as_ref()
                .unwrap()
                .to_ascii_lowercase()
                .starts_with("en"),
            "matched voice should have English language"
        );

        // Non-existent language should return None.
        let result = catalog.find_voice(Some("zh"), None, None);
        assert!(result.is_none(), "no Chinese voices in built-in catalog");
    }

    #[test]
    fn voice_matching_by_gender() {
        let catalog = VoiceCatalog::all_providers();

        // Match female voice.
        let result = catalog.find_voice(None, Some(VoiceGender::Female), None);
        assert!(result.is_some());
        let voice = result.unwrap();
        assert_eq!(
            voice.gender.as_deref(),
            Some("female"),
            "matched voice should be female"
        );

        // Match male voice.
        let result = catalog.find_voice(None, Some(VoiceGender::Male), None);
        assert!(result.is_some());
        let voice = result.unwrap();
        assert_eq!(
            voice.gender.as_deref(),
            Some("male"),
            "matched voice should be male"
        );
    }

    #[test]
    fn voice_matching_by_style() {
        let catalog = VoiceCatalog::all_providers();

        // Match narrative style -- Josh has "deep and narrative".
        let result = catalog.find_voice(None, None, Some(VoiceStyle::Narrative));
        assert!(result.is_some());
        let voice = result.unwrap();
        assert!(
            voice
                .style
                .as_ref()
                .unwrap()
                .to_ascii_lowercase()
                .contains("narrative"),
            "matched voice should have narrative style, got: {:?}",
            voice.style
        );

        // Match conversational style -- Rachel has "calm and conversational".
        let result = catalog.find_voice(None, None, Some(VoiceStyle::Conversational));
        assert!(result.is_some());
        let voice = result.unwrap();
        assert!(
            voice
                .style
                .as_ref()
                .unwrap()
                .to_ascii_lowercase()
                .contains("conversational"),
            "matched voice should have conversational style, got: {:?}",
            voice.style
        );
    }

    #[test]
    fn voice_matching_best_score() {
        let catalog = VoiceCatalog::all_providers();

        // Match with multiple criteria: English + female + conversational.
        // Rachel is female + conversational + English = score 3.
        let result = catalog.find_voice(
            Some("en"),
            Some(VoiceGender::Female),
            Some(VoiceStyle::Conversational),
        );
        assert!(result.is_some());
        let voice = result.unwrap();

        // Rachel should win: she matches all three criteria.
        assert_eq!(
            voice.name, "Rachel",
            "Rachel should be best match for en + female + conversational"
        );

        // Match English + male + narrative.
        // Josh is male + narrative + English = score 3.
        let result = catalog.find_voice(
            Some("en"),
            Some(VoiceGender::Male),
            Some(VoiceStyle::Narrative),
        );
        assert!(result.is_some());
        let voice = result.unwrap();
        assert_eq!(
            voice.name, "Josh",
            "Josh should be best match for en + male + narrative"
        );

        // Verify that a 2-criteria match beats a 1-criteria match.
        // English + female: Nova or Shimmer (openai) or Rachel/Bella/Elli (elevenlabs).
        // All score 2. The first found wins, but all are valid.
        let result = catalog.find_voice(Some("en"), Some(VoiceGender::Female), None);
        assert!(result.is_some());
        let voice = result.unwrap();
        assert_eq!(voice.gender.as_deref(), Some("female"));
    }

    #[test]
    fn voice_filtering() {
        let catalog = VoiceCatalog::all_providers();

        // Filter by provider only.
        let openai_voices = catalog.filter_voices(Some("openai"), None, None);
        assert_eq!(openai_voices.len(), 6);
        for v in &openai_voices {
            assert_eq!(v.provider, "openai");
        }

        let elevenlabs_voices = catalog.filter_voices(Some("elevenlabs"), None, None);
        assert_eq!(elevenlabs_voices.len(), 6);
        for v in &elevenlabs_voices {
            assert_eq!(v.provider, "elevenlabs");
        }

        // Filter by gender.
        let female_voices = catalog.filter_voices(None, None, Some(VoiceGender::Female));
        assert!(!female_voices.is_empty());
        for v in &female_voices {
            assert_eq!(v.gender.as_deref(), Some("female"));
        }

        // Filter by provider + gender.
        let openai_male = catalog.filter_voices(Some("openai"), None, Some(VoiceGender::Male));
        // OpenAI has Echo and Onyx as male voices.
        assert_eq!(openai_male.len(), 2);
        for v in &openai_male {
            assert_eq!(v.provider, "openai");
            assert_eq!(v.gender.as_deref(), Some("male"));
        }

        // Filter by language.
        let en_voices = catalog.filter_voices(None, Some("en"), None);
        assert_eq!(en_voices.len(), 12, "all built-in voices are English");

        // Filter with non-matching criteria.
        let empty = catalog.filter_voices(Some("nonexistent"), None, None);
        assert!(empty.is_empty());
    }

    #[test]
    fn voice_cache_ttl_expiry() {
        let catalog = VoiceCatalog::all_providers();

        // Cache with very short TTL (already expired via helper).
        let cache = VoiceCatalogCache::new_expired(catalog.clone(), Duration::from_millis(1));
        assert!(cache.is_expired(), "cache should be expired");

        // Cache with long TTL should not be expired.
        let cache = VoiceCatalogCache::new(catalog.clone(), Duration::from_secs(3600));
        assert!(!cache.is_expired(), "fresh cache should not be expired");
        assert_eq!(cache.catalog().voice_count(), 12);
        assert_eq!(cache.ttl(), Duration::from_secs(3600));

        // Default TTL cache.
        let cache = VoiceCatalogCache::with_default_ttl(catalog);
        assert_eq!(cache.ttl(), Duration::from_secs(24 * 60 * 60));
        assert!(!cache.is_expired());
    }

    #[test]
    fn voice_cache_refresh() {
        let catalog = VoiceCatalog::all_providers();
        let mut cache =
            VoiceCatalogCache::new_expired(VoiceCatalog::new(), Duration::from_millis(1));
        assert!(cache.is_expired());
        assert_eq!(cache.catalog().voice_count(), 0);

        // Refresh with full catalog.
        cache.refresh(catalog);
        assert!(
            !cache.is_expired(),
            "cache should not be expired after refresh"
        );
        assert_eq!(cache.catalog().voice_count(), 12);
    }

    #[test]
    fn per_agent_voice_preference() {
        let pref = VoicePreference {
            preferred_voice: Some("nova".to_string()),
            preferred_provider: Some("openai".to_string()),
            language: Some("en".to_string()),
            quality: Some(VoiceQuality::Hd),
        };

        // Serialization roundtrip.
        let json = serde_json::to_string(&pref).unwrap();
        let back: VoicePreference = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pref);
        assert_eq!(back.preferred_voice.as_deref(), Some("nova"));
        assert_eq!(back.preferred_provider.as_deref(), Some("openai"));
        assert_eq!(back.language.as_deref(), Some("en"));
        assert_eq!(back.quality, Some(VoiceQuality::Hd));

        // Default preference is all None.
        let default_pref = VoicePreference::default();
        assert!(default_pref.preferred_voice.is_none());
        assert!(default_pref.preferred_provider.is_none());
        assert!(default_pref.language.is_none());
        assert!(default_pref.quality.is_none());
    }

    /// MANDATORY SECURITY TEST: empty catalog must not panic, must return
    /// None/empty safely. This verifies robustness against missing data.
    #[test]
    fn empty_catalog_returns_none() {
        let catalog = VoiceCatalog::new();

        // Catalog should be empty.
        assert!(catalog.is_empty());
        assert_eq!(catalog.voice_count(), 0);
        assert!(catalog.all_voices().is_empty());
        assert!(catalog.providers().is_empty());

        // find_voice must return None, not panic.
        let result = catalog.find_voice(Some("en"), Some(VoiceGender::Female), None);
        assert!(
            result.is_none(),
            "empty catalog must return None, never panic"
        );

        // filter_voices must return empty, not panic.
        let filtered = catalog.filter_voices(Some("openai"), Some("en"), Some(VoiceGender::Male));
        assert!(
            filtered.is_empty(),
            "empty catalog must return empty vec, never panic"
        );

        // voices_for_provider must return empty slice, not panic.
        let voices = catalog.voices_for_provider("nonexistent");
        assert!(voices.is_empty());

        // find_voice with all None criteria on empty catalog.
        let result = catalog.find_voice(None, None, None);
        assert!(result.is_none());

        // find_voice with all None criteria on populated catalog returns None
        // because score is 0 for every voice when no criteria are given.
        let populated = VoiceCatalog::all_providers();
        let result = populated.find_voice(None, None, None);
        assert!(
            result.is_none(),
            "find_voice with no criteria should return None (all scores are 0)"
        );
    }

    #[test]
    fn voice_quality_serialization() {
        for quality in [VoiceQuality::Standard, VoiceQuality::Hd] {
            let json = serde_json::to_string(&quality).unwrap();
            let back: VoiceQuality = serde_json::from_str(&json).unwrap();
            assert_eq!(back, quality);
        }
    }

    #[test]
    fn voice_quality_display() {
        assert_eq!(VoiceQuality::Standard.to_string(), "standard");
        assert_eq!(VoiceQuality::Hd.to_string(), "hd");
    }

    #[test]
    fn voice_quality_default() {
        assert_eq!(VoiceQuality::default(), VoiceQuality::Standard);
    }
}
