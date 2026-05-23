//! gRPC captcha plugin binary.
//!
//! Implements the go-plugin gRPC handshake and serves the CaptchaService
//! defined in proto/captcha.proto.
//!
//! Build: cargo build --bin captcha-plugin --no-default-features

mod abstraction;
mod click;
mod error;
mod server;
mod slide;
mod w;


// Include the generated proto code.
pub mod captcha_proto {
    tonic::include_proto!("captcha");
}

use captcha_proto::captcha_service_server::{CaptchaService, CaptchaServiceServer};
use captcha_proto::{
    CalculateKeyRequest, CalculateKeyResponse, CaptchaType,
    GenerateWRequest, GenerateWResponse,
    GetCsRequest, GetCsResponse, GeetestCs,
    GetNewCsArgsRequest, GetNewCsArgsResponse, NewCsArgs,
    GetTypeRequest, GetTypeResponse,
    SolveGeetestCaptchaRequest, SolveGeetestCaptchaResponse,
    VerifyRequest, VerifyResponse,
    VersionRequest, VersionResponse,
};
use tonic::{Request, Response, Status};

use crate::abstraction::{Api, GenerateW};
use crate::click::Click;
use crate::slide::Slide;

// =============================================================================
// gRPC Service Implementation
// =============================================================================

#[derive(Default)]
pub struct CaptchaServiceImpl;

#[tonic::async_trait]
impl CaptchaService for CaptchaServiceImpl {
    async fn solve(
        &self,
        req: Request<SolveGeetestCaptchaRequest>,
    ) -> Result<Response<SolveGeetestCaptchaResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();

        let result = tokio::task::spawn_blocking(move || {
            server::solve_pipeline(&gt, &challenge)
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(validate) => Ok(Response::new(SolveGeetestCaptchaResponse {
                success: true,
                validate,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(SolveGeetestCaptchaResponse {
                success: false,
                validate: String::new(),
                error: e.to_string(),
            })),
        }
    }

    async fn get_cs(
        &self,
        req: Request<GetCsRequest>,
    ) -> Result<Response<GetCsResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();
        let w = if r.w.is_empty() { None } else { Some(r.w.clone()) };

        let result = tokio::task::spawn_blocking(move || {
            let click = Click::default();
            click.get_c_s(&gt, &challenge, w.as_deref())
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok((c, s)) => Ok(Response::new(GetCsResponse {
                success: true,
                cs: Some(GeetestCs { s, c }),
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(GetCsResponse {
                success: false,
                cs: None,
                error: e.to_string(),
            })),
        }
    }

    async fn get_type(
        &self,
        req: Request<GetTypeRequest>,
    ) -> Result<Response<GetTypeResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();
        let w = if r.w.is_empty() { None } else { Some(r.w.clone()) };

        let result = tokio::task::spawn_blocking(move || {
            let click = Click::default();
            click.get_type(&gt, &challenge, w.as_deref())
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(vt) => {
                let ct = match vt {
                    crate::abstraction::VerifyType::Click => CaptchaType::Click,
                    crate::abstraction::VerifyType::Slide => CaptchaType::Slide,
                };
                Ok(Response::new(GetTypeResponse {
                    success: true,
                    r#type: ct as i32,
                    error: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(GetTypeResponse {
                success: false,
                r#type: CaptchaType::Unknown as i32,
                error: e.to_string(),
            })),
        }
    }

    async fn get_new_cs_args(
        &self,
        req: Request<GetNewCsArgsRequest>,
    ) -> Result<Response<GetNewCsArgsResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();

        let result = tokio::task::spawn_blocking(move || {
            // Try click first, then slide.
            let click = Click::default();
            let vt = click.get_type(&gt, &challenge, None)?;

            match vt {
                crate::abstraction::VerifyType::Click => {
                    let (c, s, pic_url) = click.get_new_c_s_args(&gt, &challenge)?;
                    Ok::<_, crate::error::Error>((c, s, pic_url, String::new(), String::new(), String::new()))
                }
                crate::abstraction::VerifyType::Slide => {
                    let slide = Slide::default();
                    let (c, s, (new_challenge, full_bg, miss_bg, slider)) =
                        slide.get_new_c_s_args(&gt, &challenge)?;
                    Ok((c, s, new_challenge, full_bg, miss_bg, slider))
                }
            }
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok((c, s, new_challenge, full_bg, miss_bg, slider)) => {
                Ok(Response::new(GetNewCsArgsResponse {
                    success: true,
                    args: Some(NewCsArgs {
                        c,
                        s,
                        new_challenge,
                        full_bg_url: full_bg,
                        miss_bg_url: miss_bg,
                        slider_url: slider,
                    }),
                    error: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(GetNewCsArgsResponse {
                success: false,
                args: None,
                error: e.to_string(),
            })),
        }
    }

    async fn calculate_key(
        &self,
        req: Request<CalculateKeyRequest>,
    ) -> Result<Response<CalculateKeyResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();
        let args = r.args; // Option<NewCSArgs>

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;

            // Determine type first.
            let mut click = Click::default();
            let vt = click.get_type(&gt, &challenge, None)?;

            match vt {
                crate::abstraction::VerifyType::Click => {
                    // For click, the "key" args is the pic URL.
                    // Use full_bg_url as the pic URL for click.
                    let pic_url = if !args.full_bg_url.is_empty() {
                        args.full_bg_url.clone()
                    } else {
                        // fallback: use the download/get_new_c_s_args flow
                        let (_, _, url) = click.get_new_c_s_args(&gt, &challenge)?;
                        url
                    };
                    click.calculate_key(pic_url)
                }
                crate::abstraction::VerifyType::Slide => {
                    let mut slide = Slide::default();
                    let slide_args = (
                        args.new_challenge.clone(),
                        args.full_bg_url.clone(),
                        args.miss_bg_url.clone(),
                        args.slider_url.clone(),
                    );
                    slide.calculate_key(slide_args)
                }
            }
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(key) => Ok(Response::new(CalculateKeyResponse {
                success: true,
                key,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(CalculateKeyResponse {
                success: false,
                key: String::new(),
                error: e.to_string(),
            })),
        }
    }

    async fn generate_w(
        &self,
        req: Request<GenerateWRequest>,
    ) -> Result<Response<GenerateWResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();
        let key = r.key.clone();
        let args = r.args; // Option<NewCSArgs>

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;
            let c_ref = args.c.clone();
            let s_ref = args.s.clone();

            // Determine type first.
            let click = Click::default();
            let vt = click.get_type(&gt, &challenge, None)?;

            match vt {
                crate::abstraction::VerifyType::Click => {
                    click.generate_w(&key, &gt, &challenge, &c_ref, &s_ref)
                }
                crate::abstraction::VerifyType::Slide => {
                    let slide = Slide::default();
                    slide.generate_w(&key, &gt, &challenge, &c_ref, &s_ref)
                }
            }
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(w) => Ok(Response::new(GenerateWResponse {
                success: true,
                w,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(GenerateWResponse {
                success: false,
                w: String::new(),
                error: e.to_string(),
            })),
        }
    }

    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();
        let w = r.w.clone();

        let result = tokio::task::spawn_blocking(move || {
            let click = Click::default();
            let w_opt = if w.is_empty() { None } else { Some(w.as_str()) };
            click.verify(&gt, &challenge, w_opt)
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok((_msg, validate)) => Ok(Response::new(VerifyResponse {
                success: true,
                validate,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(VerifyResponse {
                success: false,
                validate: String::new(),
                error: e.to_string(),
            })),
        }
    }

    async fn version(
        &self,
        _req: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        Ok(Response::new(VersionResponse {
            git_commit: env!("GIT_COMMIT").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}

// =============================================================================
// Main – go-plugin gRPC handshake
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind to a random port so we know the address before the handshake.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(tokio_listener);

    // 2. Print go-plugin gRPC handshake to stdout.
    //    Format: CORE-PROTO|APP-PROTO|NETWORK|ADDR|PROTOCOL
    eprintln!("captcha-plugin: listening on {addr}");
    println!("1|1|tcp|{addr}|grpc");

    // 3. Serve gRPC.
    let svc = CaptchaServiceImpl::default();
    tonic::transport::Server::builder()
        .add_service(CaptchaServiceServer::new(svc))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
