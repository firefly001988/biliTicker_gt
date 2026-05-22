use crate::abstraction::{Api, GenerateW};
use crate::click::Click;
use crate::slide::Slide;
use std::time::Duration;

/// Run the full captcha solve pipeline for a given gt+challenge.
/// Returns Ok(validate) on success.
pub(crate) fn solve_pipeline(gt: &str, challenge: &str) -> crate::error::Result<String> {
    // Use Click as the initial handler (it can detect both types).
    // We create it here so all blocking I/O stays on one thread.
    let mut click = Click::default();

    let (_c0, _s0) = click.get_c_s(gt, challenge, None)?;
    let verify_type = click.get_type(gt, challenge, None)?;

    match verify_type {
        crate::abstraction::VerifyType::Click => {
            click.simple_match(gt, challenge)
        }
        crate::abstraction::VerifyType::Slide => {
            let mut slide = Slide::default();
            // Slide doesn't have simple_match, build the pipeline manually.
            let (_c0, _s0) = slide.get_c_s(gt, challenge, None)?;
            let (c, s, args) = slide.get_new_c_s_args(gt, challenge)?;
            let key = slide.calculate_key(args)?;
            let w = slide.generate_w(key.as_str(), gt, challenge, c.as_ref(), s.as_str())?;

            std::thread::sleep(Duration::from_secs(2));
            let (_msg, validate) = slide.verify(gt, challenge, Some(w.as_str()))?;
            Ok(validate)
        }
    }
}
