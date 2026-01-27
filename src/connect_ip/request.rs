use quiche::h3::NameValue;
use tracing::debug;

/// Default MTU value used when client doesn't provide one or parsing fails
const DEFAULT_MTU: u16 = 1500;

/// Capsule Protocol header value indicating support for the capsule protocol
const CAPSULE_PROTOCOL_VALUE: &[u8] = b"?1";

/// Builds an HTTP/3 CONNECT request for the connect-ip protocol.
///
/// Creates the necessary HTTP/3 headers for establishing a CONNECT-IP tunnel.
/// This includes the CONNECT method, connect-ip protocol identifier,
/// capsule protocol support, and MTU negotiation.
///
/// # Arguments
///
/// * `authority` - The authority (host:port) of the proxy server
/// * `path` - The request path, typically "/" for CONNECT-IP
/// * `tun_mtu` - The desired Maximum Transmission Unit for the tunnel interface
///
/// # Returns
///
/// A vector of HTTP/3 headers representing the CONNECT request
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
        quiche::h3::Header::new(b"capsule-protocol", CAPSULE_PROTOCOL_VALUE),
        quiche::h3::Header::new(b"tun-mtu", tun_mtu.as_bytes()),
    ];
    req
}

/// Builds an HTTP/3 response for a CONNECT-IP request.
///
/// Validates the incoming CONNECT-IP request headers and constructs an appropriate response.
/// If the request is valid (CONNECT method, connect-ip protocol, capsule protocol support),
/// returns a 200 status. Otherwise, returns a 405 Method Not Allowed status.
///
/// Also performs MTU negotiation by selecting the minimum of the client's requested MTU
/// and the proxy's own MTU limit.
///
/// # Arguments
///
/// * `request` - The HTTP/3 headers from the client's CONNECT request
/// * `own_tun_mtu` - The proxy's maximum supported MTU for the tunnel
///
/// # Returns
///
/// A tuple containing:
/// * Response headers (including status, capsule-protocol, and negotiated tun-mtu)
/// * The negotiated MTU value
/// * The HTTP status code (200 for success, 405 for invalid requests)
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
        (Some(b"CONNECT"), Some(b"connect-ip"), Some(CAPSULE_PROTOCOL_VALUE)) => 200,
        _ => {
            debug!(
                "Unsupported request: method={:?}, protocol={:?}, capsule_protocol={:?}",
                method, protocol, capsule_protocol
            );
            405
        }
    };

    let negotiated_mtu = if let Some(tun_mtu) = tun_mtu {
        let client_mtu = if let Ok(s) = std::str::from_utf8(tun_mtu) {
            s.parse::<u16>().unwrap_or(DEFAULT_MTU)
        } else {
            DEFAULT_MTU
        };
        std::cmp::min(client_mtu, own_tun_mtu)
    } else {
        own_tun_mtu
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", CAPSULE_PROTOCOL_VALUE),
        quiche::h3::Header::new(b"tun-mtu", negotiated_mtu.to_string().as_bytes()),
    ];

    (headers, negotiated_mtu, status)
}

/// Checks if the response headers indicate a successful CONNECT response.
///
/// Also extracts the negotiated MTU value from the response if present.
///
/// # Arguments
///
/// * `headers` - The HTTP/3 response headers from the proxy
///
/// # Returns
///
/// A tuple containing:
/// * A boolean indicating whether the connection was successfully established
/// * The negotiated MTU value if present in the tun-mtu header
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
        matches!(
            (status, capsule_protocol),
            (Some(b"200"), Some(CAPSULE_PROTOCOL_VALUE))
        ),
        tun_mtu.and_then(|mtu_bytes| {
            std::str::from_utf8(mtu_bytes)
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
        }),
    )
}

/// Converts HTTP/3 headers to string tuples for logging and debugging.
pub fn headers_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();
            (name, value)
        })
        .collect()
}
