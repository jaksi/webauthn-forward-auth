use std::{
    fs,
    sync::{Arc, RwLock},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header::HeaderMap},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    routing::post,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};
use url::form_urlencoded;
use webauthn_rs::prelude::*;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "localhost:8080")]
    listen_address: String,

    #[arg(short, long, default_value = "user.ron")]
    user_path: String,

    #[arg(short, long)]
    domain: String,

    #[arg(short, long, default_value = "auth")]
    auth_subdomain: String,

    #[arg(long, default_value_t = false)]
    allow_registration: bool,
}

struct Config {
    user_path: String,
    domain: String,
    auth_subdomain: String,
}

#[derive(Deserialize, Serialize)]
struct User {
    id: Uuid,
    passkeys: RwLock<Vec<Passkey>>,
}

impl User {
    fn init(path: &str) -> Self {
        match fs::read_to_string(path) {
            Ok(data) => ron::from_str(&data).unwrap(),
            Err(_) => User {
                id: Uuid::new_v4(),
                passkeys: RwLock::new(Vec::new()),
            },
        }
    }
    fn save(&self, path: &str) {
        fs::write(path, ron::to_string(self).unwrap()).unwrap();
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    webauthn: Arc<Webauthn>,
    user: Arc<User>,
}

#[derive(Deserialize)]
struct RedirectQuery {
    target: String,
}

async fn index(
    State(app_state): State<AppState>,
    session: Session,
    headers: HeaderMap,
) -> impl IntoResponse {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|header| header.to_str().ok())
        .unwrap_or(&app_state.config.domain);
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|header| header.to_str().ok())
        .unwrap_or("/");

    match session.get::<Uuid>("user").await.unwrap() {
        Some(_) => Ok(()),
        None => Err(Redirect::to(&format!(
            "https://{}.{}/auth?{}",
            app_state.config.auth_subdomain,
            app_state.config.domain,
            form_urlencoded::Serializer::new(String::new())
                .append_pair("target", &format!("{}{}", host, uri))
                .finish(),
        ))),
    }
}

async fn register() -> Html<&'static str> {
    Html(include_str!("register.html"))
}

async fn start_registration(
    State(app_state): State<AppState>,
    session: Session,
) -> Result<Json<CreationChallengeResponse>, StatusCode> {
    let user = "default";
    let (ccr, pr) =
        match app_state
            .webauthn
            .start_passkey_registration(app_state.user.id, user, user, None)
        {
            Ok((ccr, pr)) => (ccr, pr),
            Err(_) => {
                return Err(StatusCode::BAD_REQUEST);
            }
        };
    session.insert("reg_state", pr).await.unwrap();
    Ok(Json(ccr))
}

async fn finish_registration(
    State(app_state): State<AppState>,
    session: Session,
    Json(payload): Json<RegisterPublicKeyCredential>,
) -> Result<(), StatusCode> {
    let pr: PasskeyRegistration = match session.remove("reg_state").await.unwrap() {
        Some(pr) => pr,
        None => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let passkey = match app_state
        .webauthn
        .finish_passkey_registration(&payload, &pr)
    {
        Ok(passkey) => passkey,
        Err(_) => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    app_state.user.passkeys.write().unwrap().push(passkey);
    app_state.user.save(&app_state.config.user_path);
    Ok(())
}

async fn authenticate(redirect: Query<RedirectQuery>) -> Html<String> {
    Html(minijinja::render!(include_str!("authenticate.html"), redirect => redirect.target))
}

async fn start_authentication(
    State(app_state): State<AppState>,
    session: Session,
) -> Result<Json<RequestChallengeResponse>, StatusCode> {
    let (rcr, pa) = match app_state
        .webauthn
        .start_passkey_authentication(&app_state.user.passkeys.read().unwrap())
    {
        Ok((rcr, pa)) => (rcr, pa),
        Err(_) => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    session.insert("auth_state", pa).await.unwrap();
    Ok(Json(rcr))
}

async fn finish_authentication(
    State(app_state): State<AppState>,
    session: Session,
    Json(payload): Json<PublicKeyCredential>,
) -> Result<(), StatusCode> {
    let pa: PasskeyAuthentication = match session.remove("auth_state").await.unwrap() {
        Some(pa) => pa,
        None => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    match app_state
        .webauthn
        .finish_passkey_authentication(&payload, &pa)
    {
        Ok(_) => {
            session.insert("user", app_state.user.id).await.unwrap();
            Ok(())
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let config = Arc::new(Config {
        user_path: args.user_path.clone(),
        domain: args.domain.clone(),
        auth_subdomain: args.auth_subdomain.clone(),
    });

    let webauthn = Arc::new(
        WebauthnBuilder::new(
            &args.domain,
            &Url::parse(&format!("https://{}.{}", &args.auth_subdomain, args.domain)).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap(),
    );

    let user = Arc::new(User::init(&args.user_path));

    let app_state = AppState {
        config,
        webauthn,
        user,
    };

    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_expiry(Expiry::OnInactivity(Duration::days(1)))
        .with_domain(args.domain);

    let mut router = Router::new()
        .route("/", get(index))
        .route("/auth", get(authenticate))
        .route("/authenticate", get(start_authentication))
        .route("/authenticate", post(finish_authentication));
    if args.allow_registration {
        router = router
            .route("/reg", get(register))
            .route("/register", get(start_registration))
            .route("/register", post(finish_registration));
    }
    let app = router.with_state(app_state).layer(session_layer);
    let listener = tokio::net::TcpListener::bind(args.listen_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
