#![feature(try_trait)]

pub use jwks_client;

use actix_web::dev::{self, HttpResponseBuilder, ServiceRequest};
use actix_web::http::StatusCode;
use actix_web::Error as ActixError;
use actix_web::{web, FromRequest, HttpRequest, HttpResponse};

use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::extractors::bearer::Config as BearerConfig;
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::headers::www_authenticate::bearer::Bearer;
use actix_web_httpauth::middleware::HttpAuthentication;

use jwks_client::error::Error as JwksError;
use jwks_client::keyset::KeyStore;

use jonases_tracing_util::{log_simple_err, log_simple_err_callback};

use futures::future::{ready, Ready};

use serde::{Deserialize, Serialize};

use display_json::DisplayAsJson;

use std::option::NoneError;
use std::sync::Arc;

pub async fn init_key_set(
  certs_endpoint: &str,
) -> Result<Arc<KeyStore>, JwksError> {
  Ok(Arc::new(KeyStore::new_from(&certs_endpoint).await?))
}

pub fn jwt_validator() -> HttpAuthentication<
  BearerAuth,
  fn(
    ServiceRequest,
    BearerAuth,
  ) -> Ready<Result<ServiceRequest, ActixError>>,
> {
  HttpAuthentication::bearer(auth_wrapper)
}

fn auth_wrapper(
  req: ServiceRequest,
  bearer: BearerAuth,
) -> Ready<Result<ServiceRequest, ActixError>> {
  ready(auth(req, bearer))
}

fn auth(
  req: ServiceRequest,
  bearer: BearerAuth,
) -> Result<ServiceRequest, ActixError> {
  let config = req
    .app_data::<BearerConfig>()
    .map(|data| data.clone())
    .unwrap_or_else(Default::default);

  let key_set = req
    .app_data::<web::Data<Arc<KeyStore>>>()
    .ok_or(AuthenticationError::from(config.clone()))
    .map_err(log_simple_err_callback("could not retrieve key_set"))?;

  match key_set.verify(bearer.token()) {
    Ok(_jwt) => Ok(req),
    Err(e) => {
      log_simple_err("could not verify user access token", &e);
      Err(AuthenticationError::from(config).into())
    }
  }
}

#[derive(Serialize, Deserialize, DisplayAsJson)]
pub struct User {
  pub name: String,
  #[serde(alias = "preferred_username")]
  pub username: String,
  pub email: String,
}

impl User {
  fn init(
    req: &HttpRequest,
    payload: &mut dev::Payload,
  ) -> Result<User, Error> {
    let bearer = BearerAuth::from_request(req, payload)
      .into_inner()
      .map_err(log_simple_err_callback(
        "could not retrieve BearerAuth from request",
      ))?;

    let key_set = req
      .app_data::<web::Data<Arc<KeyStore>>>()
      .ok_or(NoneError)
      .map_err(log_simple_err_callback(
        "could not retrieve key_set",
      ))?;

    let jwt = key_set.decode(bearer.token()).map_err(
      log_simple_err_callback("could not decode user access token"),
    )?;

    let user =
      jwt.payload().into().map_err(log_simple_err_callback(
        "could not parse user access token into user object",
      ))?;

    Ok(user)
  }
}

impl FromRequest for User {
  type Config = ();
  type Future = Ready<Result<Self, Self::Error>>;
  type Error = Error;

  fn from_request(
    req: &HttpRequest,
    payload: &mut dev::Payload,
  ) -> Self::Future {
    ready(User::init(req, payload))
  }
}

#[derive(Debug, Serialize, DisplayAsJson)]
pub enum Error {
  HeaderNotFound,
  KeyStoreNotFound,
  JwksError,
}

impl From<AuthenticationError<Bearer>> for Error {
  fn from(_: AuthenticationError<Bearer>) -> Self {
    Self::HeaderNotFound
  }
}

impl From<NoneError> for Error {
  fn from(_: NoneError) -> Self {
    Self::KeyStoreNotFound
  }
}

impl From<JwksError> for Error {
  fn from(_: JwksError) -> Self {
    Self::JwksError
  }
}

impl actix_web::error::ResponseError for Error {
  fn error_response(&self) -> HttpResponse {
    let mut res = HttpResponseBuilder::new(self.status_code());
    res.json(self)
  }

  fn status_code(&self) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
  }
}
