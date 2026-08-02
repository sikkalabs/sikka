//! The HTTP surface: federation for peers, JSON-RPC for wallets.
//!
//! Both live on one port because a node is meant to be trivially deployable —
//! one container, one port, one clearnet URL. Peer messages are
//! authenticated by the signatures inside them, never by who sent the request,
//! so there is nothing here that needs TLS to be safe.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::{debug, warn};

use sikka_common::bytes::{Address, Hash};
use sikka_common::constants::MAX_HTTP_BODY_BYTES;
use sikka_common::error::Error;
use sikka_p2p::wire::{
    ErrorBody, PeersRequest, PeersResponse, SubmitCheckpoint, SubmitProposal, SubmitTransaction,
    SubmitTransactionResponse, SubmitVote, TxSyncRequest, TxSyncResponse,
};
use sikka_rpc::types::TxReceipt;
use sikka_rpc::{method, RpcError, RpcRequest, RpcResponse};

use crate::gossip::Gossip;
use crate::node::Node;

/// Shared handler state: the node, plus the means to relay what it accepts.
#[derive(Clone)]
pub struct AppState {
    pub node: Arc<Node>,
    pub gossip: Arc<Gossip>,
}

pub fn router(state: AppState) -> Router {
    // Full checkpoints are tens to hundreds of MiB of hex-encoded ML-DSA
    // material. Raise the body limit only on those POSTs; everything else
    // keeps Axum's 2 MiB default so wallets cannot force huge buffers.
    let bulk = Router::new()
        .route("/tx/sync", post(sync_transactions))
        .route("/checkpoint/proposal", post(submit_proposal))
        .route("/checkpoint/finalized", post(submit_checkpoint))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES));

    let api = Router::new()
        .route("/", get(api_index))
        .route("/health", get(health))
        .route("/ai", get(random_address))
        .route("/tx", post(submit_transaction))
        .route("/tx/{id}", get(has_transaction))
        .route("/vote", post(submit_vote))
        .route("/checkpoint/latest", get(latest_checkpoint))
        .route("/checkpoint/pending", get(pending_proposal))
        .route("/checkpoint/{height}", get(get_checkpoint))
        .route("/peers", post(peers))
        .route("/state/snapshot/manifest", get(snapshot_manifest))
        .route(
            "/state/snapshot/{snapshot_id}/chunk/{index}",
            get(snapshot_chunk),
        )
        .route("/rpc", post(rpc))
        .merge(bulk);

    Router::new()
        .nest("/api", api)
        .route("/", get(site_index))
        .route("/wallet.html", get(wallet_page))
        .route("/wallet", get(wallet_page))
        .route("/address.html", get(address_page))
        .route("/address", get(address_page))
        .layer(middleware::from_fn(cors))
        .with_state(state)
}

/// Allow browser wallets (and local `file://` pages) to call JSON-RPC.
async fn cors(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors(response.headers_mut());
        return response;
    }
    let mut response = next.run(req).await;
    apply_cors(response.headers_mut());
    response
}

fn apply_cors(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

/// An error that carries a status code chosen from the error's own nature.
struct HttpError(Error);

impl From<Error> for HttpError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            Error::CheckpointNotFound(_) => StatusCode::NOT_FOUND,
            Error::Other(msg) if msg.contains("no funded addresses") => StatusCode::NOT_FOUND,
            e if e.is_client_error() => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            warn!(error = %self.0, "request failed");
        } else {
            debug!(error = %self.0, "rejected a request");
        }
        (status, Json(ErrorBody::new(self.0))).into_response()
    }
}

type HttpResult<T> = std::result::Result<T, HttpError>;

async fn wallet_page() -> Html<&'static str> {
    Html(include_str!("../../../public/wallet.html"))
}

async fn address_page() -> Html<&'static str> {
    Html(include_str!("../../../public/address.html"))
}

async fn site_index() -> Html<&'static str> {
    Html(include_str!("../../../public/index.html"))
}

async fn api_index(State(state): State<AppState>) -> HttpResult<Json<Value>> {
    let health = state.node.health();
    Ok(Json(json!({
        "software": concat!("sikka-node/", env!("CARGO_PKG_VERSION")),
        "chain_id": health.chain_id,
        "height": health.height,
        "node": state.node.address(),
        "site": "/",
        "wallet": "/wallet.html",
        "address": "/address.html",
        "endpoints": [
            "/api/health", "/api/ai", "/api/rpc", "/api/tx", "/api/tx/sync", "/api/vote",
            "/api/checkpoint/proposal", "/api/checkpoint/finalized",
            "/api/checkpoint/latest", "/api/checkpoint/pending",
            "/api/checkpoint/{height}",
            "/api/peers", "/api/state/snapshot/manifest",
            "/api/state/snapshot/{snapshot_id}/chunk/{index}"
        ],
        "rpc_methods": method::ALL,
    })))
}

/// Random account holding at least 1 SIKKA — for the landing-page teaser.
async fn random_address(State(state): State<AppState>) -> HttpResult<Json<Value>> {
    match state.node.random_funded_address()? {
        Some(pick) => Ok(Json(json!({
            "address": pick.address,
            "balance": pick.balance,
            "bond": pick.bond,
            "total": pick.total,
        }))),
        None => Err(Error::Other("no funded addresses on this chain yet".into()).into()),
    }
}

async fn health(State(state): State<AppState>) -> Json<sikka_p2p::wire::Health> {
    Json(state.node.health())
}

async fn submit_transaction(
    State(state): State<AppState>,
    Json(body): Json<SubmitTransaction>,
) -> HttpResult<Json<SubmitTransactionResponse>> {
    let (id, accepted) = state.node.submit_transaction(body.transaction.clone())?;
    if accepted {
        state.gossip.transaction(body.transaction);
    }
    Ok(Json(SubmitTransactionResponse { id, accepted }))
}

async fn sync_transactions(
    State(state): State<AppState>,
    Json(body): Json<TxSyncRequest>,
) -> HttpResult<Json<TxSyncResponse>> {
    if !body.filter.is_acceptable() {
        return Err(Error::Other("bloom filter is malformed or oversized".into()).into());
    }
    let (transactions, filter) = state
        .node
        .sync_transactions(&body.filter, body.limit.min(5_000));
    Ok(Json(TxSyncResponse {
        transactions,
        filter,
    }))
}

async fn has_transaction(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> HttpResult<Json<Value>> {
    let id: Hash = id.parse()?;
    let status = state.node.transaction_status(&id);
    Ok(Json(json!({ "id": id, "known": status.pending })))
}

async fn submit_vote(
    State(state): State<AppState>,
    Json(body): Json<SubmitVote>,
) -> HttpResult<Json<Value>> {
    let (follow_up, finalized) = state.node.handle_vote(body.vote)?;
    if let Some(vote) = follow_up {
        state.gossip.vote(vote);
    }
    let height = finalized.as_ref().map(|f| f.checkpoint.header.height);
    if let Some(finalized) = finalized {
        state.gossip.finalized(finalized);
    }
    Ok(Json(json!({ "accepted": true, "finalized": height })))
}

async fn submit_proposal(
    State(state): State<AppState>,
    Json(body): Json<SubmitProposal>,
) -> HttpResult<Json<sikka_p2p::wire::ProposalResponse>> {
    let response = state.node.handle_proposal(&body.proposal)?;
    if let Some(vote) = &response.vote {
        // Fan the prevote out ourselves rather than relying on the proposer to
        // relay it: that is what lets a checkpoint finalize even if the proposer
        // dies mid-round.
        state.gossip.vote(vote.clone());
    }
    if let Ok(Some(precommit)) = state.node.maybe_precommit() {
        state.gossip.vote(precommit);
    }
    if let Ok(Some(finalized)) = state.node.finalize_if_quorum() {
        state.gossip.finalized(finalized);
    }
    Ok(Json(response))
}

async fn submit_checkpoint(
    State(state): State<AppState>,
    Json(body): Json<SubmitCheckpoint>,
) -> HttpResult<Json<Value>> {
    match state
        .node
        .handle_finalized(&body.checkpoint, &body.transactions, &body.evidence)
    {
        Ok(applied) => {
            if applied {
                state.gossip.finalized(crate::node::Finalized {
                    checkpoint: body.checkpoint,
                    transactions: body.transactions,
                    evidence: body.evidence,
                });
            }
            Ok(Json(
                json!({ "applied": applied, "height": state.node.height() }),
            ))
        }
        // Too far behind to replay: ask the sync loop to fetch a snapshot, and
        // tell the sender we are not there yet rather than pretending success.
        Err(Error::BadCheckpointHeight { expected, actual }) => {
            state.gossip.request_sync();
            Ok(Json(json!({
                "applied": false,
                "height": state.node.height(),
                "syncing": true,
                "expected": expected,
                "received": actual,
            })))
        }
        Err(e) => Err(e.into()),
    }
}

async fn latest_checkpoint(
    State(state): State<AppState>,
) -> HttpResult<Json<sikka_common::checkpoint::Checkpoint>> {
    Ok(Json(state.node.latest_checkpoint()?))
}

async fn pending_proposal(
    State(state): State<AppState>,
) -> HttpResult<Json<sikka_p2p::wire::PendingProposalResponse>> {
    Ok(Json(sikka_p2p::wire::PendingProposalResponse {
        proposal: state.node.open_proposal(),
    }))
}

async fn get_checkpoint(
    State(state): State<AppState>,
    Path(height): Path<u64>,
) -> HttpResult<Json<sikka_common::checkpoint::Checkpoint>> {
    Ok(Json(state.node.checkpoint(height)?))
}

async fn peers(
    State(state): State<AppState>,
    Json(body): Json<PeersRequest>,
) -> HttpResult<Json<PeersResponse>> {
    if let Some(announce) = &body.announce {
        // A bad announcement is not fatal: still answer with our peer list.
        if let Err(e) = state.node.record_announce(announce) {
            debug!(error = %e, "ignored a peer announcement");
        }
    }
    Ok(Json(PeersResponse {
        peers: state.node.peers(),
    }))
}

async fn snapshot_manifest(
    State(state): State<AppState>,
) -> HttpResult<Json<sikka_state::SnapshotManifest>> {
    let node = state.node.clone();
    let manifest = tokio::task::spawn_blocking(move || node.snapshot_manifest())
        .await
        .map_err(|e| Error::Other(format!("snapshot task failed: {e}")))??;
    Ok(Json(manifest))
}

async fn snapshot_chunk(
    State(state): State<AppState>,
    Path((snapshot_id, index)): Path<(String, u32)>,
) -> HttpResult<Response> {
    let snapshot_id: Hash = snapshot_id.parse()?;
    let (meta, path) = state.node.snapshot_chunk(&snapshot_id, index)?;
    let file_meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| Error::Storage(format!("inspect snapshot chunk {}: {e}", path.display())))?;
    if file_meta.len() != u64::from(meta.compressed_bytes) {
        return Err(Error::Storage(format!(
            "snapshot chunk {} changed size on disk",
            path.display()
        ))
        .into());
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| Error::Storage(format!("read snapshot chunk {}: {e}", path.display())))?;
    if bytes.len() != meta.compressed_bytes as usize {
        return Err(Error::Storage(format!(
            "snapshot chunk {} changed size on disk",
            path.display()
        ))
        .into());
    }
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zstd"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", meta.hash.to_hex()))
            .map_err(|e| Error::Other(format!("invalid snapshot etag: {e}")))?,
    );
    Ok(response)
}

// ---- JSON-RPC ------------------------------------------------------------

async fn rpc(State(state): State<AppState>, Json(request): Json<RpcRequest>) -> Json<RpcResponse> {
    let id = request.id.clone();
    if request.jsonrpc != "2.0" {
        return Json(RpcResponse::failure(
            id,
            RpcError::invalid_request(format!("unsupported jsonrpc version '{}'", request.jsonrpc)),
        ));
    }
    match dispatch(&state, &request).await {
        Ok(result) => Json(RpcResponse::success(id, result)),
        Err(error) => Json(RpcResponse::failure(id, error)),
    }
}

async fn dispatch(state: &AppState, request: &RpcRequest) -> std::result::Result<Value, RpcError> {
    let params = &request.params;
    match request.method.as_str() {
        method::CHAIN_INFO => value(state.node.chain_info()),
        method::ACCOUNT_GET => {
            let address = address_param(params)?;
            value(state.node.account(&address))
        }
        method::ACCOUNT_PROOF => {
            let address = address_param(params)?;
            value(state.node.account_proof(&address))
        }
        method::TX_SUBMIT => {
            let transaction: sikka_common::transaction::Transaction =
                serde_json::from_value(field(params, "transaction")?)
                    .map_err(RpcError::invalid_params)?;
            let (id, accepted) = state
                .node
                .submit_transaction(transaction.clone())
                .map_err(application)?;
            if accepted {
                state.gossip.transaction(transaction);
            }
            value(Ok::<_, Error>(TxReceipt { id, accepted }))
        }
        method::TX_STATUS => {
            let id: Hash = hash_param(params, "id")?;
            value(Ok::<_, Error>(state.node.transaction_status(&id)))
        }
        method::CHECKPOINT_GET => {
            let checkpoint = match params.get("height").and_then(Value::as_u64) {
                Some(height) => state.node.checkpoint(height),
                None => state.node.latest_checkpoint(),
            };
            value(checkpoint)
        }
        method::VALIDATOR_LIST => value(state.node.validators()),
        method::PEER_LIST => value(Ok::<_, Error>(state.node.peers())),
        method::MEMPOOL_INFO => value(Ok::<_, Error>(state.node.mempool_info())),
        unknown => Err(RpcError::method_not_found(unknown)),
    }
}

fn value<T: serde::Serialize>(
    result: std::result::Result<T, Error>,
) -> std::result::Result<Value, RpcError> {
    let value = result.map_err(application)?;
    serde_json::to_value(value).map_err(RpcError::application)
}

fn application(error: Error) -> RpcError {
    match error {
        Error::CheckpointNotFound(_) => RpcError::application(error),
        e if e.is_client_error() => RpcError::invalid_params(e),
        e => RpcError::application(e),
    }
}

fn field(params: &Value, name: &str) -> std::result::Result<Value, RpcError> {
    params
        .get(name)
        .cloned()
        .ok_or_else(|| RpcError::invalid_params(format!("missing parameter '{name}'")))
}

fn address_param(params: &Value) -> std::result::Result<Address, RpcError> {
    let raw = field(params, "address")?;
    let text = raw
        .as_str()
        .ok_or_else(|| RpcError::invalid_params("address must be a string"))?;
    text.parse().map_err(RpcError::invalid_params)
}

fn hash_param(params: &Value, name: &str) -> std::result::Result<Hash, RpcError> {
    let raw = field(params, name)?;
    let text = raw
        .as_str()
        .ok_or_else(|| RpcError::invalid_params(format!("{name} must be a string")))?;
    text.parse().map_err(RpcError::invalid_params)
}
