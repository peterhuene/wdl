//! Implementation of support for Azure Blob Storage URLs.

use std::borrow::Cow;

use anyhow::Context;
use anyhow::Result;
use tracing::warn;
use url::Url;

use crate::config::AzureStorageConfig;

/// The Azure Blob Storage domain suffix.
const AZURE_STORAGE_DOMAIN_SUFFIX: &str = ".blob.core.windows.net";

/// The name of the special root container in Azure Blob Storage.
const ROOT_CONTAINER_NAME: &str = "$root";

/// Rewrites an Azure Blob Storage URL (az://) into a HTTPS URL.
pub(crate) fn rewrite_url(url: &Url) -> Result<Url> {
    assert_eq!(url.scheme(), "az");

    let account = url
        .host_str()
        .with_context(|| format!("invalid Azure URL `{url}`: storage account name is missing"))?;

    match (url.query(), url.fragment()) {
        (None, None) => format!(
            "https://{account}{AZURE_STORAGE_DOMAIN_SUFFIX}{path}",
            path = url.path()
        ),
        (None, Some(fragment)) => {
            format!(
                "https://{account}{AZURE_STORAGE_DOMAIN_SUFFIX}{path}#{fragment}",
                path = url.path()
            )
        }
        (Some(query), None) => format!(
            "https://{account}{AZURE_STORAGE_DOMAIN_SUFFIX}{path}?{query}",
            path = url.path()
        ),
        (Some(query), Some(fragment)) => {
            format!(
                "https://{account}{AZURE_STORAGE_DOMAIN_SUFFIX}{path}?{query}#{fragment}",
                path = url.path()
            )
        }
    }
    .parse()
    .with_context(|| format!("invalid Azure URL `{url}`"))
}

/// Applies Azure SAS token authentication to the given URL.
///
/// Returns `None` if the URL is not for Azure Blob Storage.
pub(crate) fn apply_auth<'a>(config: &AzureStorageConfig, url: &'a Url) -> Option<Cow<'a, Url>> {
    // Attempt to extract the account from the domain
    let account = match url.host().and_then(|host| match host {
        url::Host::Domain(domain) => domain.strip_suffix(AZURE_STORAGE_DOMAIN_SUFFIX),
        _ => None,
    }) {
        Some(account) => account,
        None => return None,
    };

    // If the URL already has a query string, don't modify it
    if url.query().is_some() {
        return Some(Cow::Borrowed(url));
    }

    // Determine the container name; if there's only one path segment, then use the
    // root container name
    let container = match url.path_segments().and_then(|mut segments| {
        match (segments.next(), segments.next()) {
            (Some(_), None) => Some(ROOT_CONTAINER_NAME),
            (Some(container), Some(_)) => Some(container),
            _ => None,
        }
    }) {
        Some(container) => container,
        None => return Some(Cow::Borrowed(url)),
    };

    // Apply the auth token if there is one
    if let Some(token) = config
        .auth
        .get(account)
        .and_then(|containers| containers.get(container))
    {
        if url.scheme() == "https" {
            let token = token.strip_prefix('?').unwrap_or(token);
            let mut url = url.clone();
            url.set_query(Some(token));
            return Some(Cow::Owned(url));
        } else {
            // Warn if the scheme isn't https, as we won't be applying the auth.
            warn!(
                "Azure Blob Storage URL `{url}` is not using HTTPS: authentication will not be \
                 used"
            );
        }
    }

    Some(Cow::Borrowed(url))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn it_rewrites_urls() {
        let url = rewrite_url(&"az://foo/bar/baz".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "https://foo.blob.core.windows.net/bar/baz");

        let url = rewrite_url(&"az://foo/bar/baz#qux".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.blob.core.windows.net/bar/baz#qux"
        );

        let url = rewrite_url(&"az://foo/bar/baz?qux=quux".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.blob.core.windows.net/bar/baz?qux=quux"
        );

        let url =
            rewrite_url(&"az://foo/bar/baz?qux=quux&jam=cakes#frag".parse().unwrap()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://foo.blob.core.windows.net/bar/baz?qux=quux&jam=cakes#frag"
        );
    }

    #[test]
    fn it_applies_auth() {
        let mut config = AzureStorageConfig::default();
        config.auth.insert(
            "account".to_string(),
            HashMap::from_iter([
                ("container1".to_string(), "token1=foo".to_string()),
                ("container2".to_string(), "?token2=bar".to_string()),
                (ROOT_CONTAINER_NAME.to_string(), "token3=qux".to_string()),
            ]),
        );

        // Not an Azure URL
        let url = "https://example.com/bar/baz".parse().unwrap();
        assert!(apply_auth(&config, &url).is_none());

        // Not using HTTPS
        let url = "http://account.blob.core.windows.net/container1/foo"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "http://account.blob.core.windows.net/container1/foo"
        );

        // Azure URL but unknown account
        let url = "https://foo.blob.core.windows.net/bar/baz".parse().unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://foo.blob.core.windows.net/bar/baz"
        );

        // Azure URL but unknown container
        let url = "https://account.blob.core.windows.net/bar/baz"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://account.blob.core.windows.net/bar/baz"
        );

        // Matching with first auth token
        let url = "https://account.blob.core.windows.net/container1/foo"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://account.blob.core.windows.net/container1/foo?token1=foo"
        );

        // Matching with second auth token
        let url = "https://account.blob.core.windows.net/container2/foo"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://account.blob.core.windows.net/container2/foo?token2=bar"
        );

        // Matching with third auth token
        let url = "https://account.blob.core.windows.net/foo".parse().unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://account.blob.core.windows.net/foo?token3=qux"
        );

        // Matching with query params already present
        let url = "https://account.blob.core.windows.net/container1/foo?a=b"
            .parse()
            .unwrap();
        assert_eq!(
            apply_auth(&config, &url).unwrap().as_str(),
            "https://account.blob.core.windows.net/container1/foo?a=b"
        );
    }
}
