use std::str::FromStr;

use actix_cors::Cors;
use actix_web::{get, routes, web, HttpRequest, http::header::HeaderMap as ActixHeaderMap};
use actix_web::http::header;

use reqwest::{ClientBuilder, Url, header as request_header, Client, StatusCode};
use urlencoding::{decode};
use url::{Url as RustUrl};
use serde::Deserialize;

use actix_web::{
    HttpResponse,
};

use once_cell::sync::Lazy;
use reqwest::header::{ORIGIN, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT as USER_AGENT_HEADER_NAME};
use std::env;

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
static IGNORED_HEADERS: [HeaderName; 15] = [
    header::ORIGIN, header::REFERER, header::HOST, header::ACCEPT_ENCODING, header::ACCEPT_LANGUAGE, header::COOKIE, header::SET_COOKIE,
    HeaderName::from_static("x-real-ip"),
    HeaderName::from_static("x-forwarded-for"),
    HeaderName::from_static("cdn-loop"),
    HeaderName::from_static("from"),
    header::DNT,
    header::FROM,
    header::CONNECTION,
    HeaderName::from_static("priority")
];

static REDIRECT_URL: Lazy<String> = Lazy::new(|| {
    if cfg!(debug_assertions) { "http://localhost:8000".to_string() } else { format!("https://{}", PROXY_HOST_NAME) }
});
static FILTERED_HEADERS: [HeaderName; 7] = [
    header::ACCESS_CONTROL_ALLOW_ORIGIN, header::ACCESS_CONTROL_ALLOW_CREDENTIALS, header::ACCESS_CONTROL_ALLOW_HEADERS, header::ACCESS_CONTROL_ALLOW_METHODS,
    header::CACHE_CONTROL,
    header::SERVER, header::DATE
];
static FORWARDING_RESERVED_HEADERS: [&str; 2] = [
    "x-origin",
    "x-referer",
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
#[options("/generate")]
#[head("/generate")]
async fn generate_options_head(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[routes]
#[options("/redirect")]
#[head("/redirect")]
async fn redirect_options_head(_req: HttpRequest) -> HttpResponse {
    return HttpResponse::Ok()
        .finish()
}

#[get("/generate")]
async fn generate(_req: HttpRequest, query: web::Query<RedirectQuery>) -> HttpResponse {
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

    return HttpResponse::Ok().body(generate_path(unwrapped_url, _req.headers().clone()));
}

fn generate_path(url: Url, headers: ActixHeaderMap) -> String {
    let mut raw_url = url.as_str();

    if raw_url.contains("?") { raw_url = raw_url.rsplit_once("?").unwrap().0; }

    let (path, raw_file_name) = raw_url.rsplit_once("/").unwrap();

    let raw_query = url.query();

    let query = raw_query.map(|q| q.to_string()).unwrap_or_default();

    let mut header_serialized = Builder::default();

    let mut vec = Vec::new();
    for (header_name) in headers.clone().keys() {
        vec.push(header_name.to_string());
    }

    vec.sort();

    for (header_name_raw) in vec {
        let header_name_result = HeaderName::from_str(header_name_raw.as_str());
        let header_name = header_name_result.unwrap();
        let header_value = headers.get(header_name.clone()).unwrap();

        let header_string = header_name.to_string();

        if IGNORED_HEADERS.contains(&header_name) || header_string.starts_with("sec") || header_string.starts_with("cf") { continue; }

        // println!("{} {}", header_name.clone(), header_value.clone().to_str().unwrap());

        header_serialized.append(urlencoding::encode(header_name.as_ref()).into_owned());
        header_serialized.append(",");
        header_serialized.append(urlencoding::encode(header_value.to_str().unwrap_or_default()).into_owned());
        header_serialized.append("[]");
    }

    let meta = format!("{}@{}{}", path, header_serialized.string().unwrap_or_default(), if query != "" { format!("?{}", query) } else { query });
    let mut file_name = raw_file_name.to_owned();

    if file_name.contains("?") { file_name = file_name.split_once("?").unwrap().0.to_string() }

    // println!("{}", meta);

    return format!("{}/file/{}/{}", REDIRECT_URL.as_str(), CRYPTO.encrypt_str_to_base64(meta).replace("/", "-"), file_name)
}

#[get("/redirect")]
async fn redirect(_req: HttpRequest, query: web::Query<RedirectQuery>) -> HttpResponse {
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
        .append_header((header::LOCATION, generate_path(unwrapped_url, _req.headers().clone())))
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
    let meta_raw = decoded_meta.0;
    let (meta, headers_raw) = meta_raw.rsplit_once("@").unwrap_or_default();

    let raw_queries = decoded_meta.1;
    let file = req.match_info().get("file").unwrap();
    let queries = decode(raw_queries).expect("UTF-8");

    let mut headers = HeaderMap::new();
    let mut force_agent = true;

    let mut url = meta.to_owned() + "/" + file + "?" + &*queries;
    if url.ends_with("?") { url.pop(); }

    let request_headers = req.headers();
    let parsed_url = Url::parse(&*url).unwrap();

    let parsed_host = parsed_url.host_str().unwrap();
    let scheme = parsed_url.scheme();
    let constructed_host: String = format!("{}://{}", scheme, parsed_host).parse().unwrap();

    for header_name in FORWARDING_RESERVED_HEADERS {
        if !request_headers.contains_key(header_name) {
            headers.insert(HeaderName::from_str(&*header_name.replace("x-", "")).unwrap(), constructed_host.parse().unwrap());
        }
    }

    /*
    for (header_name_raw, header_value) in request_headers {
        let header_name_result = HeaderName::from_str(header_name_raw.as_str());
        let header_name = header_name_result.unwrap();
        let header_value = headers.get(header_name.clone()).unwrap();

        let header_string = header_name.to_string();

        if IGNORED_HEADERS.contains(&header_name) || header_string.starts_with("sec") || header_string.starts_with("cf") { continue; }

        let header_name_raw = header_name.to_string().to_lowercase();
        let header_name_parsed = match header_name_raw.as_str() {
            "x-origin" => "origin",
            "x-referer" => "referer",
            "x-host" => "host",
            h => &h
        };

        if header_name == header::USER_AGENT { force_agent = false; }

        println!("{} {}", HeaderName::from_str(&*header_name_parsed).unwrap(), header_value.clone().to_str().unwrap());

        headers.insert(
            HeaderName::from_str(&*header_name_parsed).unwrap(),
            header_value.clone()
        );
    }
     */

    let forwarding_raw_headers = headers_raw.split("[]");
    for forwarding_raw_header in forwarding_raw_headers {
        let (mut h, mut v) = forwarding_raw_header.split_once(",").unwrap_or_default();

        if h.is_empty() || v.is_empty() { continue; }

        let hrr = decode(h).unwrap_or_default();

        let hr = match hrr.as_ref() {
            "x-origin" => "origin",
            "x-referer" => "referer",
            "x-host" => "host",
            h => &h
        };

        let vr = decode(v).unwrap_or_default();

        // println!("{}={}", hr, vr);

        if vr == "none" {
            headers.remove(hr);
        } else {
            headers.insert(
                HeaderName::from_str(&*hr).unwrap(),
                HeaderValue::from_str(&*vr).unwrap()
            );
        }
    }

    // for (header_name, header_value) in headers.clone() {
        // println!("{}={}", header_name.unwrap(), header_value.to_str().unwrap());
    //}

    if force_agent { headers.insert(USER_AGENT_HEADER_NAME, USER_AGENT.parse().unwrap()); }

    // println!("{}", url);

    let mut leecher = false;

    if req.uri().path().ends_with(".m3u8") {
        if req.headers().get(ORIGIN).is_none() || req.headers().get(ORIGIN).unwrap() != "https://enime.moe" {
            url = "https://raw.githubusercontent.com/NADESHIKON/rick-roll-hls/master/roll.m3u8".parse().unwrap();
            leecher = true;
        }
    }

    let response = HTTP_CLIENT
        .get(url)
        .headers(headers.clone())
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
        let mut bypass_cache = false;

        if content_type.contains(M3U8_CONTENT_TYPE) || leecher {
            let response_text = response.text().await.unwrap();

            // println!("{}", meta.to_string());

            let mut forwarding_headers = ActixHeaderMap::new();
            for (h, v) in headers.clone() {
                let hc = h.unwrap().clone();
                let hrr = hc.as_str();
                let hr = match hrr {
                    "origin" => "x-origin",
                    "referer" => "x-referer",
                    "host" => "x-host",
                    h => &h
                };

                forwarding_headers.insert(hr.parse().unwrap(), v);
            }

            let mut builder = Builder::default();
            for line in response_text.split("\n") {
                if line.starts_with("#") {
                    if line.starts_with("#EXT-X-KEY") {
                        let key_url = between(line, "URI=\"", "\"");
                        builder.append(line.replace(key_url, &*generate_path(Url::parse(key_url).unwrap(), forwarding_headers.clone())));
                    } else {
                        builder.append(line);
                    }
                }
                else if !line.is_empty() {
                    let parsed_url;

                    if is_url(line) {
                        parsed_url = Url::parse(line).unwrap();
                    } else if leecher {
                        parsed_url = Url::parse(&*("https://github.com/NADESHIKON/rick-roll-hls/raw/master/".to_owned() + line)).unwrap()
                    } else {
                        parsed_url = Url::parse(&*(meta.to_owned() + "/" + line)).unwrap();
                    }

                    builder.append(generate_path(parsed_url, forwarding_headers.clone()));
                }

                builder.append("\n");
            }

            return http_response
                .body(builder.string().unwrap())
        } else if content_type.contains(HTML_CONTENT_TYPE) {
            bypass_cache = true;
        } else if file.ends_with(".m3u8") && !content_type.contains(M3U8_CONTENT_TYPE) {
            origin_error = true;
            bypass_cache = true;
        }

        if bypass_cache {
            http_response.insert_header((request_header::CACHE_CONTROL, "no-store"));
            http_response.insert_header(("CDN-Cache-Control", "no-store"));
            http_response.insert_header(("Cloudflare-CDN-Cache-Control", "no-store"));
            if origin_error && !leecher {
                http_response.status(StatusCode::FORBIDDEN); // Prevent 200 status code with 403 content..
            }
        }
    }

    return http_response.body(response.bytes().await.unwrap())
}

fn between<'a>(source: &'a str, start: &'a str, end: &'a str) -> &'a str {
    let start_position = source.find(start);

    if start_position.is_some() {
        let start_position = start_position.unwrap() + start.len();
        let source = &source[start_position..];
        let end_position = source.find(end).unwrap_or_default();
        return &source[..end_position];
    }
    return "";
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
        .service(generate_options_head)
        .service(generate)
        .wrap(Cors::default().allow_any_origin().allow_any_header().allow_any_method().supports_credentials())
    )
        .bind((if !cfg!(debug_assertions) { "0.0.0.0" } else { "127.0.0.1" }, 8000))?
        .run()
        .await
}