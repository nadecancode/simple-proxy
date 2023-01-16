use std::fmt::format;
use std::str::FromStr;
use std::time::Duration;
use actix_cors::Cors;
use actix_web::{get, guard::Host, web, Result, options, HttpRequest, Handler, Responder};
use actix_web::http::header;
use actix_web::web::resource;
use reqwest::{ClientBuilder, Url, header as request_header, Method};
use urlencoding::{decode, encode};
use url::{Host, Url as RustUrl};
use serde::Deserialize;
use futures::future::LocalBoxFuture;
use actix_web::{
    body::EitherBody,
    dev::{self, Service, ServiceRequest, ServiceResponse, Transform},
    http, Error, HttpResponse,
};
use actix_web::body::{BoxBody, MessageBody};
use actix_web_lab::middleware::{from_fn, Next};
use std::any::Any;

pub struct CORS;

static USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
static PROXY_HOST_NAME: &str = "proxy.nade.me";

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
    let host = req.uri().host();

    if !cfg!(test) && (host.is_none() || host.unwrap() != PROXY_HOST_NAME) {
        return HttpResponse::Forbidden()
            .body("Please access this via host name only.");
    }

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
        .append_header((header::LOCATION, format!("{}/file/{}/{}", if cfg!(test) { "http://localhost:8000".to_string() } else { format!("https://{}", PROXY_HOST_NAME) }, encode(path), file_name)))
        .finish()
}

#[options("/file/{meta}/{file}")]
async fn proxy_options(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[get("/file/{meta}/{file}")]
async fn proxy(req: HttpRequest) -> HttpResponse {
    let host = req.uri().host();

    if !cfg!(test) && (host.is_none() || host.unwrap() != PROXY_HOST_NAME) {
        return HttpResponse::Forbidden()
            .body("Please access this via host name only.");
    }

    let raw_meta = req.match_info().query("meta");
    let mut supplied_meta = decode(raw_meta).expect("UTF-8");
    let file = req.match_info().get("file").unwrap();
    let queries = req.query_string();

    let mut headers = header::HeaderMap::new();
    headers.insert(request_header::HeaderName::from_str("user-agent").unwrap(), request_header::HeaderValue::from_str(USER_AGENT).unwrap());

    let timeout = Duration::new(5, 0);
    let client = ClientBuilder::new().timeout(timeout).build().unwrap();

    let response = client
        .get(supplied_meta.to_string() + "/" + file + "?" + queries)
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
        .bind(("0.0.0.0", 8000))?
        .run()
        .await
}