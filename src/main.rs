use std::fmt::format;
use std::str::FromStr;
use std::time::Duration;
use actix_cors::Cors;
use actix_web::{get, guard::Host, web, Result, options, HttpRequest, Handler, Responder};
use actix_web::http::header;
use actix_web::web::resource;
use reqwest::{ClientBuilder, Url, header as request_header, Method, Client};
use urlencoding::{decode, encode};
use url::{Host, Url as RustUrl};
use serde::Deserialize;
use futures::future::{LocalBoxFuture};
use actix_web::{
    body::EitherBody,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    http, Error, HttpResponse,
};
use actix_web::body::{BoxBody, MessageBody};
use actix_web_lab::middleware::{from_fn, Next};
use std::any::Any;
use std::ops::ControlFlow;
use once_cell::sync::Lazy;
use reqwest::header::{HeaderName, USER_AGENT as USER_AGENT_HEADER_NAME};

pub struct CORS;

static USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
static PROXY_HOST_NAME: &str = "proxy.nade.me";

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    ClientBuilder::new().timeout(Duration::new(5, 0)).build().unwrap()
});
static IGNORED_HEADERS: [&str; 2] = ["x-real-ip", "x-forwarded-for"];
static REDIRECT_URL: Lazy<String> = Lazy::new(|| {
    if cfg!(test) { "http://localhost:8000".to_string() } else { format!("https://{}", PROXY_HOST_NAME) }
});

#[derive(Deserialize)]
struct RedirectQuery {
    url: String,
}

#[get("/")]
async fn index() -> &'static str {
    "こんにちわ"
}

#[get("/redirect")]
async fn redirect(req: HttpRequest, query: web::Query<RedirectQuery>) -> HttpResponse {
    let raw_url = &query.url;
    if raw_url == "" {
        return HttpResponse::BadRequest()
            .body("An URL needs to be supplied.");
    }

    let decoded_url = decode(raw_url).expect("UTF-8");
    let url = RustUrl::parse(&*decoded_url);

    if url.is_err() {
        return HttpResponse::BadRequest()
            .body(format!("A valid URL needs to be supplied. {}", url.err().unwrap()));
    }

    let parsed_url = decoded_url;
    let (path, file_name) = parsed_url.rsplit_once("/").unwrap();

    return HttpResponse::MovedPermanently()
        .append_header((header::LOCATION, format!("{}/file/{}/{}", REDIRECT_URL.as_str(), encode(path), file_name)))
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
    let queries = req.query_string();

    let mut headers = request_header::HeaderMap::new();
    let mut force_agent = true;

    for (header_name, header_value) in req.headers() {
        let mut header_name_raw = match header_name.as_str() {
            "x-origin" => "origin",
            "x-referer" => "referer",
            h => &h
        };

        let lowercase_header_name = header_name_raw.to_lowercase();

        if IGNORED_HEADERS.contains(&header_name_raw) { continue; }
        if lowercase_header_name == "user-agent" { force_agent = false; }

        headers.insert(
            HeaderName::from_str(&*lowercase_header_name).unwrap(),
            header_value.clone()
        );
    }

    if force_agent { headers.insert(USER_AGENT_HEADER_NAME, USER_AGENT.parse().unwrap()); }

    let response = HTTP_CLIENT
        .get(supplied_meta.to_string() + "/" + file + "?" + queries)
        .headers(headers)
        .send().await.unwrap();

    return HttpResponse::Ok()
        .insert_header(("content-type", response.headers().get("content-type").unwrap().to_str().unwrap()))
        .body(response.bytes().await.unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    HttpServer::new(|| App::new()
        .service(index)
        .service(proxy)
        .service(proxy_options)
        .service(redirect)
        .wrap(Cors::default().allow_any_origin().allow_any_header().allow_any_method().supports_credentials())
    )
        .bind((if !cfg!(test) { "0.0.0.0" } else { "127.0.0.1" }, 8000))?
        .run()
        .await
}