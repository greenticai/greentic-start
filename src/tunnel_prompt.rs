use std::io::{self, BufRead, IsTerminal, Write};

use crate::operator_i18n::tr;
use crate::{CloudflaredModeArg, NgrokModeArg, StartRequest};

pub(crate) fn maybe_prompt_tunnel(request: &mut StartRequest) {
    if request.tunnel_explicit {
        return;
    }
    if cfg!(test) {
        return;
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    prompt_tunnel_with_io(&mut reader, &mut writer, request);
}

fn prompt_tunnel_with_io<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    request: &mut StartRequest,
) {
    let prompt = tr(
        "cli.tunnel.prompt",
        "Tunnel service (for external provider webhooks):",
    );
    let opt_none = tr("cli.tunnel.option_none", "No tunnel (local only)");
    let opt_cloudflared = tr(
        "cli.tunnel.option_cloudflared",
        "Cloudflare Tunnel (cloudflared)",
    );
    let opt_ngrok = tr("cli.tunnel.option_ngrok", "ngrok");

    let _ = writeln!(writer, "\n{prompt}");
    let _ = writeln!(writer, "1 ) {opt_none}");
    let _ = writeln!(writer, "2 ) {opt_cloudflared}");
    let _ = writeln!(writer, "3 ) {opt_ngrok}");
    let _ = write!(writer, "> ");
    let _ = writer.flush();

    let mut input = String::new();
    if reader.read_line(&mut input).is_err() {
        return;
    }

    match input.trim() {
        "2" => {
            request.cloudflared = CloudflaredModeArg::On;
        }
        "3" => {
            request.ngrok = NgrokModeArg::On;
        }
        "1" | "" => {
            let msg = tr("cli.tunnel.selected_none", "Running without tunnel.");
            let _ = writeln!(writer, "{msg}");
        }
        _ => {
            let msg = tr(
                "cli.tunnel.invalid_selection",
                "Invalid selection. Running without tunnel.",
            );
            let _ = writeln!(writer, "{msg}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_request() -> StartRequest {
        StartRequest {
            bundle: None,
            tenant: None,
            team: None,
            no_nats: false,
            nats: crate::NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::Off,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            admin: false,
            admin_port: 8443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: false,
            passphrase_stdin: false,
            passphrase_file: None,
        }
    }

    #[test]
    fn selects_no_tunnel_on_option_1() {
        let mut input = Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        assert_eq!(request.cloudflared, CloudflaredModeArg::Off);
        assert_eq!(request.ngrok, NgrokModeArg::Off);
    }

    #[test]
    fn selects_cloudflared_on_option_2() {
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        assert_eq!(request.cloudflared, CloudflaredModeArg::On);
        assert_eq!(request.ngrok, NgrokModeArg::Off);
    }

    #[test]
    fn selects_ngrok_on_option_3() {
        let mut input = Cursor::new(b"3\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        assert_eq!(request.cloudflared, CloudflaredModeArg::Off);
        assert_eq!(request.ngrok, NgrokModeArg::On);
    }

    #[test]
    fn defaults_to_no_tunnel_on_empty_input() {
        let mut input = Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        assert_eq!(request.cloudflared, CloudflaredModeArg::Off);
        assert_eq!(request.ngrok, NgrokModeArg::Off);
    }

    #[test]
    fn defaults_to_no_tunnel_on_invalid_input() {
        let mut input = Cursor::new(b"abc\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        assert_eq!(request.cloudflared, CloudflaredModeArg::Off);
        assert_eq!(request.ngrok, NgrokModeArg::Off);
    }

    #[test]
    fn renders_prompt_with_options() {
        let mut input = Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        let mut request = make_request();
        prompt_tunnel_with_io(&mut input, &mut output, &mut request);
        let rendered = String::from_utf8(output).expect("utf8");
        assert!(rendered.contains("1 )"));
        assert!(rendered.contains("2 )"));
        assert!(rendered.contains("3 )"));
    }
}
