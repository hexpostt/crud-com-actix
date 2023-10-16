use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use database::postgres_connection;
use actix_cors::Cors;
use dotenv::dotenv;
use sqlx::{Postgres, Pool};


mod database {
    pub mod postgres_connection;
}
mod services;

#[derive(Clone)]
pub struct AppState {
    postgres_client: Pool<Postgres>,
    json_web_token: String,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Hello world"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let pg_client = postgres_connection::start_connection().await;
    let json_web_token_environment = std::env::var("JSON_WEB_TOKEN_SECRET").expect("Variavel do jwt não inserida");

    HttpServer::new(move || {
            let cors = Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            
            App::new()
                .app_data(
                    web::Data::new(AppState {
                        postgres_client: pg_client.clone(),
                        json_web_token: json_web_token_environment.clone()
                    }),
                )
                .service(index)
                .configure(services::users::services::users_routes)
                .wrap(cors)
        }
    ) 
    .bind(("127.0.0.1", 8080))?.run().await
}

