//! CBOR request/response bodies for the RPC API.
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Serialize, de::DeserializeOwned};

pub const CONTENT_TYPE: &str = "application/cbor";

pub struct Cbor<T>(pub T);

pub fn encode<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out)?;
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(b: &[u8]) -> anyhow::Result<T> {
    Ok(ciborium::from_reader(b)?)
}

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Cbor<T> {
    type Rejection = Response;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        decode(&body)
            .map(Cbor)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("cbor: {e}")).into_response())
    }
}

impl<T: Serialize> IntoResponse for Cbor<T> {
    fn into_response(self) -> Response {
        match encode(&self.0) {
            Ok(b) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], b).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}
