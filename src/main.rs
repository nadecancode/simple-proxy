use std::fmt::format;
use std::str::FromStr;
use std::time::Duration;
use actix_cors::Cors;
use actix_web::{get, head, routes, guard::Host, web, Result, options, HttpRequest, Handler, Responder};
use actix_web::http::header;
use actix_web::web::resource;
use reqwest::{ClientBuilder, Url, header as request_header, Method, Client, StatusCode};
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
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue, USER_AGENT as USER_AGENT_HEADER_NAME};
use std::env;
use actix_web::http::header::ContentType;
use lazy_static::lazy_static;
use rand::distributions::Alphanumeric;

extern crate string_builder;

use string_builder::Builder;

use magic_crypt::{new_magic_crypt, MagicCryptTrait, MagicCrypt256};

extern crate rand;
use rand::Rng;

pub struct CORS;

static USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
static PROXY_HOST_NAME: &str = "cdn.nade.me";

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    ClientBuilder::new().build().unwrap()
});
static IGNORED_HEADERS: [HeaderName; 4] = [header::ORIGIN, header::REFERER, header::HOST, header::ACCEPT_ENCODING];
static REDIRECT_URL: Lazy<String> = Lazy::new(|| {
    if cfg!(debug_assertions) { "http://localhost:8000".to_string() } else { format!("https://{}", PROXY_HOST_NAME) }
});
static FILTERED_HEADERS: [HeaderName; 7] = [
    header::ACCESS_CONTROL_ALLOW_ORIGIN, header::ACCESS_CONTROL_ALLOW_CREDENTIALS, header::ACCESS_CONTROL_ALLOW_HEADERS, header::ACCESS_CONTROL_ALLOW_METHODS,
    header::CACHE_CONTROL,
    header::SERVER, header::DATE
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
static HTML_CONTENT_TYPE: &str = "text/html";

#[derive(Deserialize)]
struct RedirectQuery {
    url: String,
}

#[get("/")]
async fn index() -> &'static str {
    "こんにちわ"
}

#[routes]
#[options("/redirect")]
#[head("/redirect")]
async fn redirect_options_head(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

fn generate_path(url: Url) -> String {
    let raw_url = url.as_str();

    let (path, mut raw_file_name) = raw_url.rsplit_once("/").unwrap();

    let raw_query = url.query();

    let query = raw_query.map(|q| q.to_string()).unwrap_or_default();

    let meta = format!("{}{}", path, if query != "" { format!("?{}", query) } else { query });
    let mut file_name = raw_file_name.to_owned();

    if file_name.contains("?") { file_name = file_name.split_once("?").unwrap().0.to_string() }

    return format!("{}/file/{}/{}", REDIRECT_URL.as_str(), CRYPTO.encrypt_str_to_base64(meta).replace("/", "-"), file_name)
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
    let unwrapped_url = url.unwrap();
    let host = unwrapped_url.host_str();

    if host.is_some() && host.unwrap() == PROXY_HOST_NAME {
        return HttpResponse::Forbidden()
            .body("You cannot proxy an URL to itself. Do not try to break the server.");
    }

    return HttpResponse::MovedPermanently()
        .append_header((header::CACHE_CONTROL, "no-store"))
        .append_header((header::LOCATION, generate_path(unwrapped_url)))
        .finish()
}

#[routes]
#[options("/file/{meta}/{file}")]
#[head("/file/{meta}/{file}")]
async fn proxy_options_head(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[get("/file/{meta}/{file}")]
async fn proxy(req: HttpRequest) -> HttpResponse {
    let raw_meta = req.match_info().query("meta").replace("-", "/");
    let supplied_meta = CRYPTO.decrypt_base64_to_string(decode(&*raw_meta).unwrap());

    if supplied_meta.is_err() {
        return HttpResponse::BadRequest()
            .body("Invalid URL.");
    }

    let supplied_unwrapped_meta = supplied_meta.unwrap();
    let decoded_meta = if !supplied_unwrapped_meta.contains("?") { (supplied_unwrapped_meta.as_str(), "") } else { supplied_unwrapped_meta.split_once("?").unwrap() };
    let meta = decoded_meta.0;
    let raw_queries = decoded_meta.1;
    let file = req.match_info().get("file").unwrap();
    let queries = decode(raw_queries).expect("UTF-8");

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

    let url = meta.to_owned() + "/" + file + "?" + &*queries;

    let response = HTTP_CLIENT
        .get(url)
        .headers(headers)
        .send().await.unwrap();

    // println!("{}", response.text().await.unwrap());

    let mut http_response = HttpResponse::Ok();

    for (header_name, header_value) in response.headers() {
        if FILTERED_HEADERS.contains(header_name) { continue; }

        http_response.insert_header((header_name, header_value));
    }

    let content_type_header = response.headers().get(CONTENT_TYPE);

    if content_type_header.is_some() {
        let content_type = content_type_header.unwrap().to_str().unwrap_or_default();
        let mut origin_error = false;

        if content_type.contains(M3U8_CONTENT_TYPE) {
            let mut response_text = response.text().await.unwrap();

            // println!("{}", meta.to_string());

            let mut builder = Builder::default();
            for line in response_text.split("\n") {
                if line.starts_with("#") { builder.append(line) }
                else if !line.is_empty() {
                    let mut parsed_url;

                    if is_url(line) {
                        parsed_url = Url::parse(line).unwrap();
                    } else {
                        parsed_url = Url::parse(&*(meta.to_owned() + "/" + line)).unwrap();
                    }

                    builder.append(generate_path(parsed_url));
                }

                builder.append("\n");
            }

            return http_response
                .body(builder.string().unwrap())
        } else if content_type.contains(HTML_CONTENT_TYPE) {
            origin_error = true;
        } else if file.ends_with(".m3u8") && !content_type.contains(M3U8_CONTENT_TYPE) {
            origin_error = true;
        }

        if origin_error {
            http_response.insert_header((request_header::CACHE_CONTROL, "no-store"));
            http_response.insert_header(("CDN-Cache-Control", "max-age=0, s-maxage=0"));
            http_response.insert_header(("Cloudflare-CDN-Cache-Control", "max-age=0, s-maxage=0"));
            http_response.status(StatusCode::FORBIDDEN); // Prevent 200 status code with 403 content..
        }
    }

    return http_response.body(response.bytes().await.unwrap())
}

extern crate lazy_static;

use regex::Regex;

const URL_REGEX: &str =
    r"https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)";

lazy_static! {
    static ref RE: Regex = {
        Regex::new(URL_REGEX).unwrap()
    };
}

pub fn is_url(url: &str) -> bool {
    return RE.is_match(url);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    HttpServer::new(|| App::new()
        .service(index)
        .service(proxy)
        .service(proxy_options_head)
        .service(redirect)
        .service(redirect_options_head)
        .wrap(Cors::default().allow_any_origin().allow_any_header().allow_any_method().supports_credentials())
    )
        .bind((if !cfg!(debug_assertions) { "0.0.0.0" } else { "127.0.0.1" }, 8000))?
        .run()
        .await
}