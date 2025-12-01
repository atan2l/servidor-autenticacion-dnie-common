use crate::db;
use crate::db::models::{OAuthGrant, OAuthGrantExtension};
use crate::db::schema::oauth_grants::code_hash;
use crate::db::schema::oauth_grants::dsl::oauth_grants;
use crate::oauth::client_cert_data::ClientCertData;
use async_trait::async_trait;
use chrono::Utc;
use diesel::{BelongingToDsl, ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
use openidconnect::core::{CoreIdToken, CoreIdTokenClaims, CoreRsaPrivateSigningKey};
use openidconnect::{
    EmptyAdditionalClaims, EndUserFamilyName, EndUserGivenName, IssuerUrl, LanguageTag,
    LocalizedClaim, StandardClaims, SubjectIdentifier,
};
use oxide_auth::primitives::grant::{Extensions, Grant, Value};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken, TokenType};
use oxide_auth_async::primitives::Issuer;
use std::sync::Arc;
use std::time::Duration;

pub struct PgIssuer<'a> {
    rsa_signing_key: &'a CoreRsaPrivateSigningKey,
    pool: Arc<db::Pool>,
    issuer: String,
}

impl<'a> PgIssuer<'a> {
    pub fn new(
        rsa_signing_key: &'a CoreRsaPrivateSigningKey,
        pool: Arc<db::Pool>,
        issuer: String,
    ) -> Self {
        Self {
            rsa_signing_key,
            pool,
            issuer,
        }
    }

    async fn get_grant(&self, code: &str) -> Option<OAuthGrant> {
        let mut conn = self.pool.get().await.ok()?;
        oauth_grants
            .filter(code_hash.eq(code))
            .select(OAuthGrant::as_select())
            .first(&mut conn)
            .await
            .ok()
    }

    async fn get_grant_extensions(&self, grant: &OAuthGrant) -> Option<Vec<OAuthGrantExtension>> {
        let mut conn = self.pool.get().await.ok()?;
        OAuthGrantExtension::belonging_to(grant)
            .select(OAuthGrantExtension::as_select())
            .load(&mut conn)
            .await
            .ok()
    }
}

#[async_trait]
impl Issuer for PgIssuer<'_> {
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let mtls_extension = grant
            .extensions
            .public()
            .find_map(|x| if x.0 == "mtls" { x.1 } else { None })
            .ok_or(())?;
        let deserialized_mtls_data: ClientCertData =
            serde_json::from_str(&mtls_extension).map_err(|_| ())?;
        let issuer_url = IssuerUrl::new(self.issuer.clone()).map_err(|_| ())?;
        let subject = SubjectIdentifier::new(grant.owner_id);
        let standard_claims = StandardClaims::new(subject);

        let mut localized_given_name = LocalizedClaim::new();
        localized_given_name.insert(
            Some(LanguageTag::new(deserialized_mtls_data.country.clone())),
            EndUserGivenName::new(deserialized_mtls_data.given_name),
        );

        let mut localized_family_name = LocalizedClaim::new();
        localized_family_name.insert(
            Some(LanguageTag::new(deserialized_mtls_data.country)),
            EndUserFamilyName::new(deserialized_mtls_data.surname),
        );

        let standard_claims = standard_claims.set_given_name(Some(localized_given_name));
        let standard_claims = standard_claims.set_family_name(Some(localized_family_name));

        let now = Utc::now();
        let id_token_claims = CoreIdTokenClaims::new(
            issuer_url,
            vec![],
            now,
            grant.until,
            standard_claims,
            EmptyAdditionalClaims::default(),
        );

        let id_token = CoreIdToken::new(
            id_token_claims,
            self.rsa_signing_key,
            RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .map_err(|_| ())?;

        Ok(IssuedToken {
            token: id_token.to_string(),
            refresh: None,
            until: grant.until,
            token_type: TokenType::Bearer,
        })
    }

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()> {
        Err(())
    }

    async fn recover_token(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        let base_grant = self.get_grant(code).await.ok_or(())?;
        let grant_extensions = self.get_grant_extensions(&base_grant).await.ok_or(())?;

        let mut extensions = Extensions::new();
        for grant_extension in grant_extensions {
            extensions.set_raw(
                grant_extension.name,
                Value::Public(Some(grant_extension.value)),
            )
        }
        Ok(Some(Grant {
            owner_id: base_grant.owner_id.to_string(),
            client_id: base_grant.client_id.to_string(),
            scope: base_grant.scope.parse().map_err(|_| ())?,
            redirect_uri: base_grant.redirect_uri.parse().map_err(|_| ())?,
            until: Utc::now() + Duration::from_mins(5),
            extensions,
        }))
    }

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()> {
        Ok(None)
    }
}
