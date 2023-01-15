use std::fmt::format;
use std::time::Duration;
use actix_cors::Cors;
use actix_web::{get, web, Result, options, HttpRequest, HttpResponse};
use actix_web::http::header;
use actix_web::web::resource;
use reqwest::{ClientBuilder, Url};
use urlencoding::{decode, encode};
use url::Url as RustUrl;
use serde::Deserialize;

pub struct CORS;

#[get("/")]
async fn index() -> &'static str {
    "こんにちわ"
}

#[derive(Deserialize)]
struct RedirectQuery {
    url: String,
}

#[get("/redirect")]
async fn redirect(query: web::Query<RedirectQuery>) -> HttpResponse {
    let raw_url = &query.url;
    if raw_url == "" {
        return HttpResponse::BadRequest()
            .body("An URL needs to be supplied.");
    }

    let decoded_url = decode(raw_url).expect("UTF-8");
    let url = RustUrl::parse(&*decoded_url);

    println!("{}", url.is_err());

    if url.is_err() {
        return HttpResponse::BadRequest()
            .body(format!("A valid URL needs to be supplied. {}", url.err().unwrap()));
    }

    let parsed_url = decoded_url;
    let (path, file_name) = parsed_url.rsplit_once("/").unwrap();

    return HttpResponse::MovedPermanently()
        .append_header((header::LOCATION, format!("https://proxy.nade.me/file/{}/{}", encode(path), file_name)))
        .finish()
}

#[options("/file/{meta}/{file}")]
async fn proxy_options(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[get("/file/{meta}/{file}")]
async fn proxy(req: HttpRequest) -> HttpResponse {
    let raw_meta = req.match_info().query("meta");
    let mut supplied_meta = decode(raw_meta).expect("UTF-8");
    let file = req.match_info().get("file").unwrap();

    let timeout = Duration::new(5, 0);
    let client = ClientBuilder::new().timeout(timeout).build().unwrap();

    let response = client.get(supplied_meta.to_string() + "/" + file).send().await.unwrap();

    return HttpResponse::Ok()
        .insert_header(("content-type", response.headers().get("content-type").unwrap().to_str().unwrap()))
        .body(response.bytes().await.unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    HttpServer::new(|| App::new()
        .wrap(Cors::default().allow_any_origin().supports_credentials())
        .service(index)
        .service(proxy)
        .service(redirect)
    )
        .bind(("0.0.0.0", 80))?
        .run()
        .await
}