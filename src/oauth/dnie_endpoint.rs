use oxide_auth::endpoint;
use oxide_auth::endpoint::{OAuthError, Template, WebRequest};
use oxide_auth_async::endpoint::{Endpoint, OwnerSolicitor};
use oxide_auth_async::primitives;
use oxide_auth_axum::{OAuthRequest, WebError};

pub struct DnieEndpoint<'a, Registrar, Authorizer, Issuer, Solicitor, Scopes> {
    pub registrar: &'a Registrar,
    pub authorizer: &'a mut Authorizer,
    pub issuer: &'a mut Issuer,
    pub solicitor: &'a mut Solicitor,
    pub scopes: &'a mut Scopes,
}

impl<'a, Registrar, Authorizer, Issuer, Solicitor, Scopes> Endpoint<OAuthRequest>
    for DnieEndpoint<'a, Registrar, Authorizer, Issuer, Solicitor, Scopes>
where
    Registrar: primitives::Registrar + Send + Sync,
    Authorizer: primitives::Authorizer + Send + Sync,
    Issuer: primitives::Issuer + Send + Sync,
    Solicitor: OwnerSolicitor<OAuthRequest> + Send + Sync,
    Scopes: endpoint::Scopes<OAuthRequest> + Send + Sync,
{
    type Error = WebError;

    fn registrar(&self) -> Option<&(dyn primitives::Registrar + Sync)> {
        Some(self.registrar)
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn primitives::Authorizer + Send)> {
        Some(self.authorizer)
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn primitives::Issuer + Send)> {
        Some(self.issuer)
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<OAuthRequest> + Send)> {
        Some(self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn endpoint::Scopes<OAuthRequest>> {
        Some(self.scopes)
    }

    fn response(
        &mut self,
        request: &mut OAuthRequest,
        kind: Template,
    ) -> Result<<OAuthRequest as WebRequest>::Response, Self::Error> {
        Ok(Default::default())
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        err.into()
    }

    fn web_error(&mut self, err: <OAuthRequest as WebRequest>::Error) -> Self::Error {
        err
    }
}
