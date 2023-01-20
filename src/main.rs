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
use reqwest::header::{HeaderName, HeaderValue, USER_AGENT as USER_AGENT_HEADER_NAME};
use std::env;
use rand::distributions::Alphanumeric;

use magic_crypt::{new_magic_crypt, MagicCryptTrait, MagicCrypt256};

extern crate rand;
use rand::Rng;

pub struct CORS;

static USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
static PROXY_HOST_NAME: &str = "proxy.nade.me";

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    ClientBuilder::new().build().unwrap()
});
static IGNORED_HEADERS: [HeaderName; 4] = [header::ORIGIN, header::REFERER, header::HOST, header::ACCEPT_ENCODING];
static REDIRECT_URL: Lazy<String> = Lazy::new(|| {
    if cfg!(debug_assertions) { "http://localhost:8000".to_string() } else { format!("https://{}", PROXY_HOST_NAME) }
});
static FILTERED_HEADERS: [HeaderName; 5] = [
    header::ACCESS_CONTROL_ALLOW_ORIGIN, header::ACCESS_CONTROL_ALLOW_CREDENTIALS, header::ACCESS_CONTROL_ALLOW_HEADERS, header::ACCESS_CONTROL_ALLOW_METHODS,
    header::CACHE_CONTROL
];

static CRYPTO: Lazy<MagicCrypt256> = Lazy::new(|| {
    new_magic_crypt!(ENCRYPTION_KEY.as_str(), 256)
});

static ENCRYPTION_KEY: Lazy<String> = Lazy::new(|| {
    let key = env::var("key");

    if key.is_ok() {
        return key.unwrap();
    }


    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(14)
        .map(char::from)
        .collect()
});

static M3U8_CONTENT_TYPE: &str = "application/vnd.apple.mpegurl";

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
        .append_header((header::LOCATION, format!("{}/file/{}/{}", REDIRECT_URL.as_str(), CRYPTO.encrypt_str_to_base64(path).replace("/", "-"), file_name)))
        .finish()
}

#[options("/file/{meta}/{file}")]
async fn proxy_options(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[get("/file/{meta}/{file}")]
async fn proxy(req: HttpRequest) -> HttpResponse {
    let raw_meta = req.match_info().query("meta").replace("-", "/");
    let mut supplied_meta = CRYPTO.decrypt_base64_to_string(decode(&*raw_meta).unwrap());

    if supplied_meta.is_err() {
        return HttpResponse::BadRequest()
            .body("Invalid URL.");
    }

    let meta = supplied_meta.unwrap();
    let file = req.match_info().get("file").unwrap();
    let queries = req.query_string();

    let mut headers = request_header::HeaderMap::new();
    let mut force_agent = true;

    for (header_name, header_value) in req.headers() {
        if IGNORED_HEADERS.contains(header_name) { continue; }

        let header_name_raw = header_name.to_string().to_lowercase();
        let mut header_name_parsed = match header_name_raw.as_str() {
            "x-origin" => "origin",
            "x-referer" => "referer",
            "x-host" => "host",
            h => &h
        };

        if header_name == header::USER_AGENT { force_agent = false; }

        // println!("{} {}", HeaderName::from_str(&*header_name_parsed).unwrap(), header_value.clone().to_str().unwrap());

        headers.insert(
            HeaderName::from_str(&*header_name_parsed).unwrap(),
            header_value.clone()
        );
    }

    if force_agent { headers.insert(USER_AGENT_HEADER_NAME, USER_AGENT.parse().unwrap()); }

    let response = HTTP_CLIENT
        .get(meta.to_string() + "/" + file + "?" + queries)
        .headers(headers)
        .send().await.unwrap();

    // println!("{}", response.text().await.unwrap());

    let mut http_response = HttpResponse::Ok();

    for (header_name, header_value) in response.headers() {
        if FILTERED_HEADERS.contains(header_name) { continue; }

        http_response.insert_header((header_name, header_value));
    }

    let content_type_header = response.headers().get(header::CONTENT_TYPE);

    if content_type_header.is_some() && content_type_header.unwrap() == M3U8_CONTENT_TYPE {
        let mut response_text = response.text().await.unwrap();

        response_text = response_text.replace(&format!("{}/", meta.to_string()), "");

        return http_response
            .body(response_text)
    }

    return http_response.body(response.bytes().await.unwrap())
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
        .bind((if !cfg!(debug_assertions) { "0.0.0.0" } else { "127.0.0.1" }, 8000))?
        .run()
        .await
}