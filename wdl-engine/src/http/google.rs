//! Implementation of support for Google Cloud Storage URLs.

use std::borrow::Cow;

use anyhow::Context;
use anyhow::Result;
use tracing::warn;
use url::Url;

use crate::config::GoogleStorageConfig;

/// The Google Storage domain.
const GOOGLE_STORAGE_DOMAIN: &str = "storage.googleapis.com";

/// Rewrites a Google Cloud Storage URL (gs://) into a HTTPS URL.
pub(crate) fn rewrite_url(url: &Url) -> Result<Url> {
    assert_eq!(url.scheme(), "gs");

    let bucket = url.host_str().with_context(|| {
        format!("invalid Google Cloud Storage URL `{url}`: bucket name is missing")
    })?;

    match (url.query(), url.fragment()) {
        (None, None) => format!(
            "https://{bucket}.{GOOGLE_STORAGE_DOMAIN}{path}",
            path = url.path()
        ),
        (None, Some(fragment)) => {
            format!(
                "https://{bucket}.{GOOGLE_STORAGE_DOMAIN}{path}#{fragment}",
                path = url.path()
            )
        }
        (Some(query), None) => format!(
            "https://{bucket}.{GOOGLE_STORAGE_DOMAIN}{path}?{query}",
            path = url.path()
        ),
        (Some(query), Some(fragment)) => {
            format!(
                "https://{bucket}.{GOOGLE_STORAGE_DOMAIN}{path}?{query}#{fragment}",
                path = url.path()
            )
        }
    }
    .parse()
    .with_context(|| format!("invalid Google Cloud Storage URL `{url}`"))
}

/// Applies Google Cloud Storage presigned signatures to the given URL.
///
/// Returns `None` if the URL is not for Azure Blob Storage.
pub(crate) fn apply_auth<'a>(config: &GoogleStorageConfig, url: &'a Url) -> Option<Cow<'a, Url>> {
    // Find the prefix of the domain; if empty, it indicates a path style URL
    let prefix = match url.host().and_then(|host| match host {
        url::Host::Domain(domain) => domain.strip_suffix(GOOGLE_STORAGE_DOMAIN),
        _ => None,
    }) {
        Some(prefix) => prefix,
        None => return None,
    };

    // If the URL already has a query string, don't modify it
    if url.query().is_some() {
        return Some(Cow::Borrowed(url));
    }

    // There are two supported URL formats:
    // 1) Path style e.g. `https://storage.googleapis.com/<bucket>/<object>`
    // 2) Virtual-host style, e.g. `https://<bucket>.storage.googleapis.com/<object>`.
    let bucket = if prefix.is_empty() {
        // This is a path style URL; bucket is first path segment
        match url.path_segments().and_then(|mut segments| segments.next()) {
            Some(bucket) => bucket,
            None => return Some(Cow::Borrowed(url)),
        }
    } else {
        // This is a virtual-host style URL; bucket should be followed with a single dot
        let mut iter = prefix.split('.');
        match (iter.next(), iter.next(), iter.next()) {
            (Some(bucket), Some(""), None) => bucket,
            _ => return Some(Cow::Borrowed(url)),
        }
    };

    if let Some(sig) = config.auth.get(bucket) {
        if url.scheme() == "https" {
            let sig = sig.strip_prefix('?').unwrap_or(sig);
            let mut url = url.clone();
            url.set_query(Some(sig));
            return Some(Cow::Owned(url));
        } else {
            // Warn if the scheme isn't https, as we won't be applying the auth.
            warn!(
                "Google Cloud Storage URL `{url}` is not using HTTPS: authentication will not be \
                 used"
            );
        }
    }

    Some(Cow::Borrowed(url))
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn it_rewrites_urls() {
        let url = rewrite_url(&"gs://foo/bar/baz".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "https://foo.storage.googleapis.com/bar/baz");

        let url = rewrite_url(&"gs://foo/bar/baz#qux".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.storage.googleapis.com/bar/baz#qux"
        );

        let url = rewrite_url(&"gs://foo/bar/baz?qux=quux".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.storage.googleapis.com/bar/baz?qux=quux"
        );

        let url =
            rewrite_url(&"gs://foo/bar/baz?qux=quux&jam=cakes#frag".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.storage.googleapis.com/bar/baz?qux=quux&jam=cakes#frag"
        );
    }

    #[test]
    fn it_applies_auth() {
        let mut config = GoogleStorageConfig::default();
        config
            .auth
            .insert("bucket1".to_string(), "token1=foo".to_string());

        config
            .auth
            .insert("bucket2".to_string(), "?token2=bar".to_string());

        // Not an GS URL
        let url = "https://example.com/bar/baz".parse().unwrap();
        assert!(apply_auth(&config, &url).is_none());

        // Not using HTTPS
        let url = "http://storage.googleapis.com/bucket1/foo/bar"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "http://storage.googleapis.com/bucket1/foo/bar"
        );

        // Unknown bucket (path)
        let url = "https://storage.googleapis.com/foo/bar/baz"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://storage.googleapis.com/foo/bar/baz"
        );

        // Unknown bucket (vhost)
        let url = "https://foo.storage.googleapis.com/bar/baz"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://foo.storage.googleapis.com/bar/baz"
        );

        // Matching with first auth token (path)
        let url = "https://storage.googleapis.com/bucket1/foo/bar"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://storage.googleapis.com/bucket1/foo/bar?token1=foo"
        );

        // Matching with first auth token (vhost)
        let url = "https://bucket1.storage.googleapis.com/foo/bar"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://bucket1.storage.googleapis.com/foo/bar?token1=foo"
        );

        // Matching with second auth token (path)
        let url = "https://storage.googleapis.com/bucket2/foo/bar"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://storage.googleapis.com/bucket2/foo/bar?token2=bar"
        );

        // Matching with second auth token (vhost)
        let url = "https://bucket2.storage.googleapis.com/foo/bar"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://bucket2.storage.googleapis.com/foo/bar?token2=bar"
        );

        // Matching with query params already present
        let url = "https://storage.googleapis.com/bucket2/foo/bar?a=b"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://storage.googleapis.com/bucket2/foo/bar?a=b"
        );
    }
}
