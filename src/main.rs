//! gRPC captcha plugin binary.
//!
//! Implements the go-plugin gRPC handshake and serves separate
//! ClickService and SlideService defined in proto/captcha.proto.
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

pub mod health_proto {
    tonic::include_proto!("grpc.health.v1");
}

use captcha_proto::click_service_server::{ClickService, ClickServiceServer};
use captcha_proto::slide_service_server::{SlideService, SlideServiceServer};
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

use health_proto::health_check_response::ServingStatus;
use health_proto::health_server::{Health, HealthServer};
use health_proto::{HealthCheckRequest, HealthCheckResponse};

use crate::abstraction::{Api, GenerateW};
use crate::click::Click;
use crate::slide::Slide;

// =============================================================================
// ClickService – handles click-based captcha solving
// =============================================================================

#[derive(Default)]
pub struct ClickServiceImpl;

#[tonic::async_trait]
impl ClickService for ClickServiceImpl {
    async fn solve(
        &self,
        req: Request<SolveGeetestCaptchaRequest>,
    ) -> Result<Response<SolveGeetestCaptchaResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut click = Click::default();
            click.simple_match(&gt, &challenge)
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
            let click = Click::default();
            let (c, s, pic_url) = click.get_new_c_s_args(&gt, &challenge)?;
            Ok::<_, crate::error::Error>(NewCsArgs {
                c,
                s,
                full_bg_url: pic_url,
                new_challenge: String::new(),
                miss_bg_url: String::new(),
                slider_url: String::new(),
            })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(args) => Ok(Response::new(GetNewCsArgsResponse {
                success: true,
                args: Some(args),
                error: String::new(),
            })),
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
        let args = r.args;

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;

            // Click uses full_bg_url as the pic URL.
            let pic_url = if !args.full_bg_url.is_empty() {
                args.full_bg_url.clone()
            } else {
                let click = Click::default();
                let (_, _, url) = click.get_new_c_s_args(&gt, &challenge)?;
                url
            };

            let mut click = Click::default();
            click.calculate_key(pic_url)
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
        let args = r.args;

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;
            let click = Click::default();
            click.generate_w(&key, &gt, &challenge, &args.c, &args.s)
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
// SlideService – handles slide-based captcha solving
// =============================================================================

#[derive(Default)]
pub struct SlideServiceImpl;

#[tonic::async_trait]
impl SlideService for SlideServiceImpl {
    async fn solve(
        &self,
        req: Request<SolveGeetestCaptchaRequest>,
    ) -> Result<Response<SolveGeetestCaptchaResponse>, Status> {
        let r = req.into_inner();
        let gt = r.gt.clone();
        let challenge = r.challenge.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut slide = Slide::default();
            let (_c0, _s0) = slide.get_c_s(&gt, &challenge, None)?;
            let (c, s, args) = slide.get_new_c_s_args(&gt, &challenge)?;
            let key = slide.calculate_key(args)?;
            let w = slide.generate_w(key.as_str(), &gt, &challenge, c.as_ref(), s.as_str())?;

            std::thread::sleep(std::time::Duration::from_secs(2));
            let (_msg, validate) = slide.verify(&gt, &challenge, Some(w.as_str()))?;
            Ok::<_, crate::error::Error>(validate)
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
            let slide = Slide::default();
            slide.get_c_s(&gt, &challenge, w.as_deref())
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
            }))
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
            let slide = Slide::default();
            let (c, s, (new_challenge, full_bg, miss_bg, slider)) =
                slide.get_new_c_s_args(&gt, &challenge)?;
            Ok::<_, crate::error::Error>(NewCsArgs {
                c,
                s,
                new_challenge,
                full_bg_url: full_bg,
                miss_bg_url: miss_bg,
                slider_url: slider,
            })
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking failed: {e}")))?;

        match result {
            Ok(args) => Ok(Response::new(GetNewCsArgsResponse {
                success: true,
                args: Some(args),
                error: String::new(),
            })),
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
        let args = r.args;

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;
            let mut slide = Slide::default();
            let slide_args = (
                args.new_challenge.clone(),
                args.full_bg_url.clone(),
                args.miss_bg_url.clone(),
                args.slider_url.clone(),
            );
            slide.calculate_key(slide_args)
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
        let args = r.args;

        let result = tokio::task::spawn_blocking(move || {
            let args = args.ok_or_else(|| {
                crate::error::other_without_source("missing NewCSArgs")
            })?;
            let slide = Slide::default();
            slide.generate_w(&key, &gt, &challenge, &args.c, &args.s)
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
            let slide = Slide::default();
            let w_opt = if w.is_empty() { None } else { Some(w.as_str()) };
            slide.verify(&gt, &challenge, w_opt)
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
// gRPC Health Check Service (grpc.health.v1.Health)
// =============================================================================

#[derive(Default)]
pub struct HealthServiceImpl;

#[tonic::async_trait]
impl Health for HealthServiceImpl {
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: ServingStatus::Serving as i32,
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

    // 3. Override stdout to a file for plugin logs.
    use stdio_override::StdoutOverride;
    let file_name = "./captcha.log";
    let guard = StdoutOverride::from_file(file_name)?;

    // 4. Serve gRPC – both Click and Slide services.
    let click_svc = ClickServiceImpl::default();
    let slide_svc = SlideServiceImpl::default();
    let health_svc = HealthServiceImpl::default();
    tonic::transport::Server::builder()
        .add_service(HealthServer::new(health_svc))
        .add_service(ClickServiceServer::new(click_svc))
        .add_service(SlideServiceServer::new(slide_svc))
        .serve_with_incoming(incoming)
        .await?;

    drop(guard);

    Ok(())
}
