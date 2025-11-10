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
