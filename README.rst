Actix JWT Validator Middleware
==============================

Simple ``actix`` middleware that takes a ``JWT`` bearer token from the
``authorization`` HTTP header and validates it against some
``JWKS``.

Example
-------

.. code:: rust

   use actix_web::{HttpServer, App};

   use actix_jwt_validator_middleware::{jwt_validator, init_key_set};

   async fn index() -> &'static str {
     "Welcome!"
   }

   #[actix_web::main]
   async fn main() -> std::io::Result<()> {
     let key_set = init_key_set("url-to-your-certification-endpoint")
       .await
       .unwrap();

     HttpServer::new(move || {
       App::new()
         .data(key_set.clone())
         .wrap(jwt_validator())
         .route("/index.html", web::get().to(index))
     })
     .bind("0.0.0.0:8080")?
     .run()
     .await
   }

TODO
----

* User object extraction from ``JWT`` payload also in this library
