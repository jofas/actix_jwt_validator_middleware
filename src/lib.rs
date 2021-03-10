pub use jwks_client;

use actix_web::Error as ActixError;
use actix_web::{dev::ServiceRequest, web};

use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::extractors::bearer::Config as BearerConfig;
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;

use jwks_client::error::Error as JwksError;
use jwks_client::keyset::KeyStore;

use jonases_tracing_util::{log_simple_err, log_simple_err_callback};

use futures::future::{ready, Ready};

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
