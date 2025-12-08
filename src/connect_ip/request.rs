use quiche::h3::NameValue;
use tracing::debug;

/// Builds an HTTP/3 CONNECT request for the connect-ip protocol.
pub fn build_request(authority: String, path: String, tun_mtu: u16) -> Vec<quiche::h3::Header> {
    let authority = authority.as_bytes();
    let path = path.as_bytes();
    let tun_mtu = tun_mtu.to_string();
    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", authority),
        quiche::h3::Header::new(b":path", path),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"tun-mtu", tun_mtu.as_bytes()),
    ];
    req
}

/// Builds an HTTP/3 response given a request.
pub fn build_response(
    request: &[quiche::h3::Header],
    own_tun_mtu: u16,
) -> (Vec<quiche::h3::Header>, u16, u16) {
    let mut method = None;
    let mut protocol = None;
    let mut capsule_protocol = None;
    let mut tun_mtu = None;

    for hdr in request {
        match hdr.name() {
            b":protocol" => protocol = Some(hdr.value()),

            b":method" => method = Some(hdr.value()),

            b"capsule-protocol" => capsule_protocol = Some(hdr.value()),

            b"tun-mtu" => tun_mtu = Some(hdr.value()),

            _ => (),
        }
    }

    let status = match (method, protocol, capsule_protocol) {
        (Some(b"CONNECT"), Some(b"connect-ip"), Some(b"?1")) => 200,
        _ => {
            debug!(
                "Unsupported request: method={:?}, protocol={:?}, capsule_protocol={:?}",
                method, protocol, capsule_protocol
            );
            405
        }
    };

    let negotiated_mtu = if let Some(tun_mtu) = tun_mtu {
        let client_mtu = std::str::from_utf8(tun_mtu)
            .unwrap_or("1500")
            .parse::<u16>()
            .unwrap_or(1500);
        std::cmp::min(client_mtu, own_tun_mtu)
    } else {
        own_tun_mtu
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", "?1".as_bytes()),
        quiche::h3::Header::new(b"tun-mtu", negotiated_mtu.to_string().as_bytes()),
    ];

    (headers, negotiated_mtu, status)
}

/// Checks if the response headers indicate a successful CONNECT response.
pub fn check_response(headers: &[quiche::h3::Header]) -> (bool, Option<u16>) {
    // Handle response headers and start capsule protocol
    let mut capsule_protocol = None;
    let mut status = None;
    let mut tun_mtu = None;
    for hdr in headers {
        match hdr.name() {
            b":status" => status = Some(hdr.value()),
            b"capsule-protocol" => capsule_protocol = Some(hdr.value()),
            b"tun-mtu" => tun_mtu = Some(hdr.value()),
            _ => (),
        }
    }

    (
        matches!((status, capsule_protocol), (Some(b"200"), Some(b"?1"))),
        tun_mtu.and_then(|mtu_bytes| {
            std::str::from_utf8(mtu_bytes)
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
        }),
    )
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
