use quiche::h3::NameValue;
use tracing::debug;

/// Builds an HTTP/3 CONNECT request for the connect-ip protocol.
pub fn build_request(authority: String, path: String) -> Vec<quiche::h3::Header> {
    let authority = authority.as_bytes();
    let path = path.as_bytes();
    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", authority),
        quiche::h3::Header::new(b":path", path),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    req
}

/// Builds an HTTP/3 response given a request.
pub fn build_response(request: &[quiche::h3::Header]) -> Vec<quiche::h3::Header> {
    let mut method = None;
    let mut protocol = None;

    for hdr in request {
        match hdr.name() {
            b":protocol" => protocol = Some(hdr.value()),

            b":method" => method = Some(hdr.value()),

            _ => (),
        }
    }

    let status = match (method, protocol) {
        (Some(b"CONNECT"), Some(b"connect-ip")) => 200,
        _ => {
            debug!(
                "Unsupported request: method={:?}, protocol={:?}",
                method, protocol
            );
            405
        }
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", "?1".as_bytes()),
    ];

    headers
}

/// Checks if the response headers indicate a successful CONNECT response.
pub fn check_response(headers: &[quiche::h3::Header]) -> bool {
    // Handle response headers and start capsule protocol
    let mut capsule_protocol = None;
    let mut status = None;
    for hdr in headers {
        match hdr.name() {
            b":status" => status = Some(hdr.value()),
            b"capsule-protocol" => capsule_protocol = Some(hdr.value()),
            _ => (),
        }
    }

    match (status, capsule_protocol) {
        (Some(b"200"), Some(b"?1")) => (),
        _ => {
            return false;
        }
    };
    true
}

pub fn headers_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();
            (name, value)
        })
        .collect()
}
