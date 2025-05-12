use std::str::FromStr;

use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::Router;
use axum::{extract::State, Json};
use http_server::router::RouterBuilder;
use instrumentation::middleware::APP_INSTALLATION_ID_HEADER_NAME;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tracing::{error, instrument};
use types::authn_authz::cognito::{CognitoUser, CognitoUsername};
use userpool::userpool::{UserPoolError, UserPoolService};
use utoipa::{OpenApi, ToSchema};

use account::service::{FetchAccountByAuthKeyInput, Service as AccountService};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bdk_utils::bdk::bitcoin::secp256k1::PublicKey;
use errors::ApiError;
use feature_flags::service::Service as FeatureFlagsService;
use http_server::swagger::{SwaggerEndpoint, Url};
use types::account::identifiers::AccountId;
use types::account::entities::Fido2Credential;
use wsm_rust_client::{SigningService, WsmClient};

use crate::debug_utils::log_debug_info_if_applicable;
use crate::metrics::{FACTORY, FACTORY_NAME};

#[derive(Clone, axum_macros::FromRef)]
pub struct RouteState(
    pub UserPoolService,
    pub AccountService,
    pub WsmClient,
    pub FeatureFlagsService,
);

impl RouterBuilder for RouteState {
    fn unauthed_router(&self) -> Router {
        Router::new()
            .route("/api/recovery-auth", post(authenticate_with_recovery))
            .route("/api/fido2-auth", post(authenticate_with_fido2)) // New endpoint replacing hw-auth
            .route("/api/fido2-register", post(register_fido2_credential)) // New endpoint for registration
            .route("/api/authenticate", post(authenticate))
            .route("/api/authenticate/tokens", post(get_tokens))
            // .route("/api/attestation/wsm", get(acquire_wsm_attestation_document))
            // .route("/api/secure-channel/initiate", post(initiate_wsm_secure_channel))
            .route_layer(FACTORY.route_layer(FACTORY_NAME.to_owned()))
            .with_state(self.to_owned())
    }
}

impl From<RouteState> for SwaggerEndpoint {
    fn from(_: RouteState) -> Self {
        (
            Url::new("Authentication", "/docs/authentication/openapi.json"),
            ApiDoc::openapi(),
        )
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        authenticate,
        authenticate_with_fido2,
        register_fido2_credential,
        authenticate_with_recovery,
        get_tokens,
    ),
    components(
        schemas(
            AuthRequestKey,
            AuthenticateWithFido2Request,
            AuthenticateWithFido2Response,
            Fido2RegistrationRequest,
            Fido2RegistrationResponse,
            AuthenticateWithRecoveryAuthkeyRequest,
            AuthenticateWithRecoveryResponse,
            AuthenticationRequest,
            AuthenticationResponse,
            ChallengeResponseParameters,
            CognitoUsername,
            GetTokensRequest,
            GetTokensResponse,
        ),
    ),
    tags(
        (name = "Authentication", description = "Account Authentication")
    )
)]
struct ApiDoc;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticateWithRecoveryAuthkeyRequest {
    pub recovery_auth_pubkey: PublicKey,
}

impl From<AuthenticateWithRecoveryAuthkeyRequest> for AuthRequestKey {
    fn from(request: AuthenticateWithRecoveryAuthkeyRequest) -> Self {
        AuthRequestKey::RecoveryPubkey(request.recovery_auth_pubkey)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticateWithRecoveryResponse {
    pub username: CognitoUsername,
    pub account_id: AccountId,
    pub challenge: String,
    pub session: String,
}

//TODO[BKR-608]: Remove this once we're using /api/authenticate
#[instrument(
    fields(username),
    skip(account_service, user_pool_service, feature_flags_service)
)]
#[utoipa::path(
    post,
    path = "/api/recovery-auth",
    request_body = AuthenticateWithRecoveryAuthkeyRequest,
    responses(
        (status = 200, description = "Authentication Challenge and Session", body=AuthenticateWithRecoveryResponse),
        (status = 404, description = "Account not found")
    ),
)]
pub async fn authenticate_with_recovery(
    State(account_service): State<AccountService>,
    State(user_pool_service): State<UserPoolService>,
    State(feature_flags_service): State<FeatureFlagsService>,
    headers: HeaderMap,
    Json(request): Json<AuthenticateWithRecoveryAuthkeyRequest>,
) -> Result<Json<AuthenticateWithRecoveryResponse>, ApiError> {
    let pubkey = request.recovery_auth_pubkey;

    if let Some(app_installation_id) = headers
        .get(APP_INSTALLATION_ID_HEADER_NAME)
        .and_then(|id| id.to_str().ok())
    {
        log_debug_info_if_applicable(
            &feature_flags_service,
            app_installation_id,
            &AuthRequestKey::from(request),
        );
    }

    let pubkeys_to_account = account_service
        .fetch_account_id_by_recovery_pubkey(FetchAccountByAuthKeyInput { pubkey })
        .await?;

    tracing::Span::current().record("account_id", pubkeys_to_account.id.to_string());

    let user = CognitoUser::Recovery(pubkeys_to_account.id.clone());
    let auth_challenge = user_pool_service
        .initiate_auth_for_user(user, &pubkeys_to_account)
        .await
        .map_err(|e| {
            let msg = "Failed to initiate authentication with pubkey";
            error!("{msg}: {e}");
            ApiError::GenericInternalApplicationError(msg.to_string())
        })?;
    Ok(Json(AuthenticateWithRecoveryResponse {
        username: CognitoUser::Recovery(pubkeys_to_account.id.clone()).into(),
        account_id: pubkeys_to_account.id,
        challenge: auth_challenge.challenge,
        session: auth_challenge.session,
    }))
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticateWithFido2Request {
    pub credential_id: String,
    pub authenticator_data: String,   // Base64 encoded authenticator data
    pub signature: String,            // Base64 encoded signature
    pub client_data_json: String,     // Base64 encoded client data JSON
}

impl From<AuthenticateWithFido2Request> for AuthRequestKey {
    fn from(request: AuthenticateWithFido2Request) -> Self {
        let credential = Fido2Credential {
            credential_id: request.credential_id,
            public_key: Vec::new(), // Will be populated during verification
            aaguid: String::new(),
            sign_count: 0,
            user_handle: String::new(),
            rp_id: String::new(),
        };
        AuthRequestKey::Fido2Credential(credential)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticateWithFido2Response {
    pub account_id: AccountId,
    pub challenge: String,
    pub session: String,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct Fido2RegistrationRequest {
    pub attestation_response: String, // Base64 encoded attestation response
    pub client_data_json: String,     // Base64 encoded client data JSON
}

#[derive(Serialize, Deserialize, Debug, PartialEq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct Fido2RegistrationResponse {
    pub credential_id: String,
    pub public_key: String, // Base64 encoded public key
}

#[instrument(
    fields(account_id),
    skip(account_service, user_pool_service, feature_flags_service)
)]
#[utoipa::path(
    post,
    path = "/api/fido2-auth",
    request_body = AuthenticateWithFido2Request,
    responses(
        (status = 200, description = "Authentication Challenge and Session", body=AuthenticateWithFido2Response),
        (status = 404, description = "Account not found")
    ),
)]
pub async fn authenticate_with_fido2(
    State(account_service): State<AccountService>,
    State(user_pool_service): State<UserPoolService>,
    State(feature_flags_service): State<FeatureFlagsService>,
    headers: HeaderMap,
    Json(request): Json<AuthenticateWithFido2Request>,
) -> Result<Json<AuthenticateWithFido2Response>, ApiError> {
    let credential_id = request.credential_id.clone();

    if let Some(app_installation_id) = headers
        .get(APP_INSTALLATION_ID_HEADER_NAME)
        .and_then(|id| id.to_str().ok())
    {
        log_debug_info_if_applicable(
            &feature_flags_service,
            app_installation_id,
            &AuthRequestKey::from(request),
        );
    }

    let pubkeys_to_account = account_service
        .fetch_account_id_by_fido2_credential_id(FetchAccountByAuthKeyInput { 
            credential_id 
        })
        .await?;

    tracing::Span::current().record("account_id", pubkeys_to_account.id.to_string());

    let user = CognitoUser::Fido2(pubkeys_to_account.id.clone());
    let auth_challenge = user_pool_service
        .initiate_auth_for_user(user, &pubkeys_to_account)
        .await
        .map_err(|e| {
            let msg = "Failed to initiate authentication with FIDO2 credential";
            error!("{msg}: {e}");
            ApiError::GenericInternalApplicationError(msg.to_string())
        })?;
    Ok(Json(AuthenticateWithFido2Response {
        account_id: pubkeys_to_account.id,
        challenge: auth_challenge.challenge,
        session: auth_challenge.session,
    }))
}

#[instrument(
    fields(account_id),
    skip(account_service)
)]
#[utoipa::path(
    post,
    path = "/api/fido2-register",
    request_body = Fido2RegistrationRequest,
    responses(
        (status = 200, description = "FIDO2 Credential Registration", body=Fido2RegistrationResponse),
        (status = 400, description = "Invalid registration data"),
        (status = 500, description = "Internal server error")
    ),
)]
pub async fn register_fido2_credential(
    State(account_service): State<AccountService>,
    Json(request): Json<Fido2RegistrationRequest>,
) -> Result<Json<Fido2RegistrationResponse>, ApiError> {
    // 1. Parse and verify the attestation response
    // 2. Extract the credential ID and public key
    // 4. Return the credential ID and public key
    
    let credential_id = BASE64.decode(&request.attestation_response)
        .map_err(|_| ApiError::GenericBadRequest("Invalid attestation response".to_string()))?;
    
    let public_key = vec![0u8; 32]; // Placeholder
    
    Ok(Json(Fido2RegistrationResponse {
        credential_id: BASE64.encode(&credential_id),
        public_key: BASE64.encode(&public_key),
    }))
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub enum AuthRequestKey {
    Fido2Credential(types::account::entities::Fido2Credential),
    AppPubkey(PublicKey),
    RecoveryPubkey(PublicKey),
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticationRequest {
    pub auth_request_key: AuthRequestKey,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthenticationResponse {
    pub username: CognitoUsername,
    pub account_id: AccountId,
    pub challenge: String,
    pub session: String,
}

#[instrument(
    fields(account_id),
    skip(account_service, user_pool_service, feature_flags_service)
)]
#[utoipa::path(
    post,
    path = "/api/authenticate",
    request_body = AuthenticationRequest,
    responses(
        (status = 200, description = "Authentication Challenge and Session", body=AuthenticateWithHardwareResponse),
        (status = 404, description = "Account not found")
    ),
)]
pub async fn authenticate(
    State(account_service): State<AccountService>,
    State(user_pool_service): State<UserPoolService>,
    State(feature_flags_service): State<FeatureFlagsService>,
    headers: HeaderMap,
    Json(request): Json<AuthenticationRequest>,
) -> Result<Json<AuthenticationResponse>, ApiError> {
    if let Some(app_installation_id) = headers
        .get(APP_INSTALLATION_ID_HEADER_NAME)
        .and_then(|id| id.to_str().ok())
    {
        log_debug_info_if_applicable(
            &feature_flags_service,
            app_installation_id,
            &request.auth_request_key,
        );
    }

    let (requested_cognito_user, pubkeys_to_account) = match request.auth_request_key {
        AuthRequestKey::Fido2Credential(credential) => {
            let pubkeys_to_account = account_service
                .fetch_account_id_by_fido2_credential_id(FetchAccountByAuthKeyInput { 
                    credential_id: credential.credential_id 
                })
                .await?;
            (
                CognitoUser::Fido2(pubkeys_to_account.id.clone()),
                pubkeys_to_account,
            )
        }
        AuthRequestKey::AppPubkey(pubkey) => {
            let pubkeys_to_account = account_service
                .fetch_account_id_by_app_pubkey(FetchAccountByAuthKeyInput { pubkey })
                .await?;
            (
                CognitoUser::App(pubkeys_to_account.id.clone()),
                pubkeys_to_account,
            )
        }
        AuthRequestKey::RecoveryPubkey(pubkey) => {
            let pubkeys_to_account = account_service
                .fetch_account_id_by_recovery_pubkey(FetchAccountByAuthKeyInput { pubkey })
                .await?;
            (
                CognitoUser::Recovery(pubkeys_to_account.id.clone()),
                pubkeys_to_account,
            )
        }
    };

    tracing::Span::current().record("account_id", pubkeys_to_account.id.to_string());

    let auth_challenge = user_pool_service
        .initiate_auth_for_user(requested_cognito_user, &pubkeys_to_account)
        .await
        .map_err(|e| {
            let msg = "Failed to initiate authentication with pubkey";
            error!("{msg}: {e}");
            ApiError::GenericInternalApplicationError(msg.to_string())
        })?;

    Ok(Json(AuthenticationResponse {
        username: auth_challenge.username,
        account_id: pubkeys_to_account.id,
        challenge: auth_challenge.challenge,
        session: auth_challenge.session,
    }))
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ChallengeResponseParameters {
    pub username: CognitoUsername,
    pub challenge_response: String,
    pub session: String,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTokensRequest {
    pub challenge: Option<ChallengeResponseParameters>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTokensResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i32,
    pub refresh_token_expires_in: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetAttestationDocumentResponse {
    pub document_b64: String,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct InitiateWsmSecureChannelResponse {
    pub noise_bundle: String,
}

#[instrument(fields(account_id), skip(user_pool_service))]
#[utoipa::path(
    post,
    path = "/api/authenticate/tokens",
    request_body = GetTokensRequest,
    responses(
        (status = 200, description = "Authentication Tokens", body=GetTokensResponse),
        (status = 404, description = "Account not found")
    ),
)]
pub async fn get_tokens(
    State(user_pool_service): State<UserPoolService>,
    Json(request): Json<GetTokensRequest>,
) -> Result<Json<GetTokensResponse>, ApiError> {
    let (challenge_present, refresh_token_present) =
        (request.challenge.is_some(), request.refresh_token.is_some());
    if challenge_present && refresh_token_present {
        return Err(ApiError::GenericBadRequest(
            "Cannot provide a challenge response and a refresh token".to_string(),
        ));
    }
    if !(challenge_present || refresh_token_present) {
        return Err(ApiError::GenericBadRequest(
            "Must provide a challenge response or a refresh token".to_string(),
        ));
    }

    let tokens = if let Some(refresh_token) = request.refresh_token {
        user_pool_service
            .refresh_access_token(refresh_token)
            .await
            .map_err(|e: UserPoolError| {
                let msg = "failed to refresh access tokens";
                error!("{msg}: {e}");
                ApiError::from(e)
            })?
    } else if let Some(params) = request.challenge {
        // There's an app bug in which the hw auth path always passes the account ID as the username here instead of
        // the username that's returned from the authenticate call. Other than this bug, usernames should never be
        // raw account IDs anymore (and will error when parsed). So in this case, use the hardware username.
        let username = match (
            CognitoUser::from_str(params.username.as_ref()),
            CognitoUser::from_str(&format!("{}-hardware", params.username.as_ref())),
        ) {
            (Err(_), Ok(hardware_user)) => hardware_user.into(),
            (_, _) => params.username,
        };

        user_pool_service
            .respond_to_auth_challenge(&username, params.session, params.challenge_response)
            .await
            .map_err(|e: UserPoolError| {
                let msg = "failed to complete auth challenge";
                error!("{msg}: {e}");
                ApiError::from(e)
            })?
    } else {
        return Err(ApiError::GenericInternalApplicationError(
            "Could not deserialize refresh token or challenge response".to_string(),
        ));
    };

    Ok(Json(GetTokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        refresh_token_expires_in: tokens.refresh_token_expires_in,
    }))
}

#[instrument(skip(wsm_client))]
#[utoipa::path(
    get,
    path = "/api/attestation/wsm",
    responses(
        (status = 200, description = "Attestation document", body=GetAttestationDocumentResponse),
        (status = 500, description = "Failed to acquire attestation document"),
    ),
)]
pub async fn acquire_wsm_attestation_document(
    State(wsm_client): State<WsmClient>,
) -> Result<Json<GetAttestationDocumentResponse>, ApiError> {
    let rsp = wsm_client.get_attestation_document().await.map_err(|e| {
        let msg = "Failed to acquire attestation document";
        error!("{msg}: {e}");
        ApiError::GenericInternalApplicationError(msg.to_string())
    })?;

    Ok(Json(GetAttestationDocumentResponse {
        document_b64: BASE64.encode(rsp.document),
    }))
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct NoiseInitiateBundleRequest {
    #[serde_as(as = "Base64")]
    pub bundle: Vec<u8>,
    pub server_static_pubkey: String,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct NoiseInitiateBundleResponse {
    #[serde_as(as = "Base64")]
    pub bundle: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub noise_session: Vec<u8>,
}

#[instrument(skip(wsm_client))]
#[utoipa::path(post, path = "/api/secure-channel/initiate")]
pub async fn initiate_wsm_secure_channel(
    State(wsm_client): State<WsmClient>,
    Json(request): Json<NoiseInitiateBundleRequest>,
) -> Result<Json<NoiseInitiateBundleResponse>, ApiError> {
    let rsp = wsm_client
        .initiate_secure_channel(request.bundle, &request.server_static_pubkey)
        .await
        .map_err(|e| {
            let msg = "Failed to initiate secure channel";
            error!("{msg}: {e}");
            ApiError::GenericInternalApplicationError(msg.to_string())
        })?;

    Ok(Json(NoiseInitiateBundleResponse {
        bundle: rsp.bundle,
        noise_session: rsp.noise_session,
    }))
}
