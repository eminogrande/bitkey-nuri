use std::collections::HashMap;

use account::service::Service as AccountService;
use authn_authz::authorizer::AuthorizerConfig;
use aws_utils::secrets_manager::test::TestSecretsManager;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{http, Router};
use bdk_utils::bdk::bitcoin::secp256k1;
use database::ddb;
use database::ddb::Repository;
use external_identifier::ExternalIdentifier;
use feature_flags::config::Config;
use http_body_util::BodyExt;
use http_server::config;
use http_server::router::RouterBuilder;
use jwt_authorizer::IntoLayer;
use partnerships::routes::RouteState;
use repository::account::AccountRepository;
use repository::consent::ConsentRepository;
use serde_json::{json, Value};
use server::test_utils::AuthenticatedRequest;
use tower::ServiceExt;
use types::account::identifiers::AccountId;
use ulid::Ulid;
use userpool::userpool::{FakeCognitoConnection, UserPoolService};

async fn test_route_state(overrides: HashMap<String, String>) -> RouteState {
    let secrets = HashMap::from([
        (
            "fromagerie-api/partnerships/signet_faucet/config".to_owned(),
            r#"{"display_name":"Signet Faucet","quote_url":"","purchase_url":"https://signet.bc-2.jp/","purchase_redirect_type":"WIDGET","partner":"SignetFaucet","partner_id":"","network":"signet", "sale_url":"https://signetfaucet.com/", "sale_redirect_type":"WIDGET"}"#.to_owned(),
        ),
        (
            "fromagerie-api/partnerships/testnet_faucet/config".to_owned(),
            r#"{"display_name":"Testnet Faucet","quote_url":"","transfer_url":"https://testnet-faucet.mempool.co/","transfer_redirect_type":"WIDGET","partner":"TestnetFaucet","partner_id":"","network":"testnet", "sale_url":"https://bitcoinfaucet.uo1.net/send.php", "sale_redirect_type":"WIDGET"}"#.to_owned(),
        ),
    ]);
    let user_pool_service = UserPoolService::new(Box::new(FakeCognitoConnection::new()));
    let feature_flags_service = Config::new_with_overrides(overrides)
        .to_service()
        .await
        .expect("Error initializing feature flags service");
    let conn = config::extract::<ddb::Config>(Some("test"))
        .unwrap()
        .to_connection()
        .await;
    let account_service = AccountService::new(
        AccountRepository::new(conn.clone()),
        ConsentRepository::new(conn),
        user_pool_service.clone(),
    );
    RouteState::from_secrets_manager(
        TestSecretsManager::new(secrets),
        user_pool_service,
        feature_flags_service,
        account_service,
    )
    .await
}

async fn authed_router(overrides: HashMap<String, String>) -> Router {
    let authorizer = AuthorizerConfig::Test
        .into_authorizer()
        .build()
        .await
        .unwrap()
        .into_layer();

    test_route_state(overrides)
        .await
        .basic_validation_router()
        .layer(authorizer)
}

async fn call_api(
    app: Router,
    authenticated: bool,
    method: http::Method,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let body = match body {
        Some(body) => Body::from(body.to_owned()),
        None => Body::empty(),
    };

    let mut request_builder = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref());
    if authenticated {
        request_builder = request_builder.authenticated(
            &AccountId::new(Ulid::new()).unwrap(),
            Some(secp256k1::SecretKey::from_slice(&[0xcd; 32]).unwrap()),
            Some(secp256k1::SecretKey::from_slice(&[0xab; 32]).unwrap()),
        );
    }
    let request = request_builder.body(body).unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();

    if authenticated {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        (status, body)
    } else {
        (status, Value::Null)
    }
}

fn partner_blocklist_overrides(blocklist_csv: &str) -> HashMap<String, String> {
    HashMap::from([
        (
            "f8e-purchase-partner-blocklist".to_string(),
            blocklist_csv.to_string(),
        ),
        (
            "f8e-transfer-partner-blocklist".to_string(),
            blocklist_csv.to_string(),
        ),
        (
            "f8e-sale-partner-blocklist".to_string(),
            blocklist_csv.to_string(),
        ),
    ])
}

#[tokio::test]
async fn transfers() {
    let app = authed_router(partner_blocklist_overrides("")).await;

    let request_body = json!({
        "country": "US",
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/transfers",
        Some(&request_body.to_string()),
    )
    .await;

    // Expected due to test configs, Testnet doesn't actually support transfers
    let expected_body = json!({
        "partners": [
            {
                "logo_url": null,
                "name": "Testnet Faucet",
                "partner": "TestnetFaucet",
                "logo_badged_url": null
            }]
    });
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn transfers_unauthorized_error() {
    let app = authed_router(partner_blocklist_overrides("")).await;

    let request_body = json!({
        "country": "US",
    });

    let (status, _) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/transfers",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transfers_redirect_unauthorized_error() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "address": "x",
        "partner": "SignetFaucet"
    });

    let (status, _) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/transfers/redirects",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn quotes() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "country": "US"
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/purchases/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    let expected_body = json!({
        "quotes": [
            {
                "crypto_amount": 0.0,
                "crypto_price": 0.0,
                "fiat_currency": "USD",
                "network_fee_crypto": 0.0,
                "network_fee_fiat": 0.0,
                "partner_info": {
                    "logo_url": null,
                    "name": "Signet Faucet",
                    "partner": "SignetFaucet",
                    "logo_badged_url": null
                },
                "user_fee_fiat": 0.0
            }
        ]
    });
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn quotes_with_blocklist() {
    let app = authed_router(partner_blocklist_overrides("SignetFaucet")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "country": "US"
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/purchases/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    let expected_body = json!({
        "quotes": []
    });
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn quotes_unauthorized_error() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "country": "US"
    });

    let (status, _) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/purchases/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn purchases_redirect() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "address": "x",
        "partner": "SignetFaucet"
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/purchases/redirects",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let redirect_info = body.get("redirect_info").unwrap();
    assert_eq!(redirect_info.get("app_restrictions"), Some(&Value::Null));
    assert_eq!(
        redirect_info.get("redirect_type"),
        Some(&Value::String("WIDGET".to_string()))
    );
    assert_eq!(
        redirect_info.get("url"),
        Some(&Value::String("https://signet.bc-2.jp/".to_string()))
    );
}

#[tokio::test]
async fn purchases_redirect_unauthorized_error() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "fiat_amount": 100,
        "fiat_currency": "USD",
        "payment_method": "CARD",
        "address": "x",
        "partner": "SignetFaucet"
    });

    let (status, _) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/purchases/redirects",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn purchase_options() {
    let (status, _body) = call_api(
        authed_router(partner_blocklist_overrides("")).await,
        true,
        http::Method::GET,
        "/api/partnerships/purchases/options?country=US&fiat_currency=USD",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn purchase_options_unauthorized_error() {
    let (status, _) = call_api(
        authed_router(HashMap::new()).await,
        false,
        http::Method::GET,
        "/api/partnerships/purchases/options?country=US&fiat_currency=USD",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn partner_transactions() {
    let (status, _body) = call_api(
        authed_router(HashMap::new()).await,
        true,
        http::Method::GET,
        "/api/partnerships/partners/SignetFaucet/transactions/test-transaction-id",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn partner_sell_transactions() {
    let (status, _body) = call_api(
        authed_router(HashMap::new()).await,
        true,
        http::Method::GET,
        "/api/partnerships/partners/SignetFaucet/transactions/test-transaction-id?type=SALE",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn get_partner() {
    let (status, body) = call_api(
        authed_router(HashMap::new()).await,
        true,
        http::Method::GET,
        "/api/partnerships/partners/SignetFaucet",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Signet Faucet");
}

#[tokio::test]
async fn sales_quotes() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "country": "US",
        "crypto_amount": 0.01,
        "fiat_currency": "USD"
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/sales/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    let expected_body = json!({
        "quotes": [
            {
                "crypto_amount": 0.01,
                "fiat_amount": 0.0,
                "fiat_currency": "USD",
                "partner_info": {
                    "logo_url": null,
                    "name": "Signet Faucet",
                    "partner": "SignetFaucet",
                    "logo_badged_url": null
                },
                "user_fee_fiat": 0.0
            },
            {
                "crypto_amount": 0.01,
                "fiat_amount": 0.0,
                "fiat_currency": "USD",
                "partner_info": {
                    "logo_url": null,
                    "name": "Testnet Faucet",
                    "partner": "TestnetFaucet",
                    "logo_badged_url": null
                },
                "user_fee_fiat": 0.0
            }
        ]
    });
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn sales_quotes_with_blocklist() {
    let app = authed_router(partner_blocklist_overrides("SignetFaucet,TestnetFaucet")).await;
    let request_body = json!({
        "country": "US",
        "crypto_amount": 0.01,
        "fiat_currency": "USD"
    });

    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/sales/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    let expected_body = json!({
        "quotes": []
    });
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn sales_quotes_unauthorized_error() {
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "country": "US",
        "crypto_amount": 0.01,
        "fiat_currency": "USD"
    });

    let (status, _body) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/sales/quotes",
        Some(&request_body.to_string()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sales_redirect_without_crypto_amount() {
    // arrange
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "refund_address": "bc1qxyykaq57n2h23ar8j2xcmv2zd0afsnkxz2rmcxv29vdaqj4mnfdqrus7hy",
        "fiat_amount": 18.12,
        "fiat_currency": "USD",
        "partner": "SignetFaucet",
    });

    // act
    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/sales/redirects",
        Some(&request_body.to_string()),
    )
    .await;
    let redirect_info = body.get("redirect_info").unwrap();

    // assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(redirect_info.get("app_restrictions"), Some(&Value::Null));
    assert_eq!(
        redirect_info.get("redirect_type"),
        Some(&Value::String("WIDGET".to_string()))
    );
    assert_eq!(
        redirect_info.get("url"),
        Some(&Value::String("https://signetfaucet.com/".to_string()))
    );
}

#[tokio::test]
async fn sales_redirect_with_crypto_amount() {
    // arrange
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "refund_address": "bc1qxyykaq57n2h23ar8j2xcmv2zd0afsnkxz2rmcxv29vdaqj4mnfdqrus7hy",
        "fiat_amount": 18.12,
        "fiat_currency": "USD",
        "crypto_amount": 0.1,
        "crypto_currency": "BTC",
        "partner": "SignetFaucet",
    });

    // act
    let (status, body) = call_api(
        app,
        true,
        http::Method::POST,
        "/api/partnerships/sales/redirects",
        Some(&request_body.to_string()),
    )
    .await;
    let redirect_info = body.get("redirect_info").unwrap();

    // assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(redirect_info.get("app_restrictions"), Some(&Value::Null));
    assert_eq!(
        redirect_info.get("redirect_type"),
        Some(&Value::String("WIDGET".to_string()))
    );
    assert_eq!(
        redirect_info.get("url"),
        Some(&Value::String("https://signetfaucet.com/".to_string()))
    );
}

#[tokio::test]
async fn sale_redirect_unauthorized_error() {
    // arrange
    let app = authed_router(partner_blocklist_overrides("")).await;
    let request_body = json!({
        "refund_address": "bc1qxyykaq57n2h23ar8j2xcmv2zd0afsnkxz2rmcxv29vdaqj4mnfdqrus7hy",
        "fiat_amount": 18.12,
        "fiat_currency": "USD",
        "partner": "SignetFaucet",
    });

    // act
    let (status, _) = call_api(
        app,
        false,
        http::Method::POST,
        "/api/partnerships/sales/redirects",
        Some(&request_body.to_string()),
    )
    .await;

    // assert
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
