use crate::{Error, Repr, Uri};
use core::convert::TryInto;

#[inline]
fn uncoded_pchar(b: u8) -> bool {
    unreserved(b) || sub_delims(b) || matches!(b, b':' | b'@')
}
#[inline]
fn hexdig(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'A'..=b'F')
}
#[inline]
fn sub_delims(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}
#[inline]
fn unreserved(b: u8) -> bool {
    scheme_char(b) || matches!(b, b'~')
}
#[inline]
fn scheme_char(b: u8) -> bool {
    alpha(b) || digit(b) || matches!(b, b'-' | b'.' | b'_')
}
#[inline]
fn digit(b: u8) -> bool {
    matches!(b, b'0'..=b'9')
}
#[inline]
fn alpha(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z')
}

fn port(
    mut bytes: &[u8],
    scheme_sep: u32,
    userinfo_sep: u32,
    port_sep: u32,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b'0'..=b'9', rest @ ..] => rest,
            [b'/', rest @ ..] | rest @ [] => {
                return path(
                    rest,
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    f(bytes).try_into().map_err(|_| Error::too_large())?,
                    f,
                )
            }
            _ => return Err(Error::todo()),
        }
    }
}

fn host(
    mut bytes: &[u8],
    scheme_sep: u32,
    userinfo_sep: u32,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    if let [b'[', ip_literal @ ..] = bytes {
        let following = match ip_literal {
            [b'v', d, ver @ ..] if hexdig(*d) => {
                let mut ip_future = ver;
                let mut addr = loop {
                    ip_future = match ip_future {
                        [d, rest @ ..] if hexdig(*d) => rest,
                        [b'.', c, rest @ ..]
                            if unreserved(*c) || sub_delims(*c) || matches!(c, b':') =>
                        {
                            break rest
                        }
                        _ => return Err(Error::todo()),
                    }
                };
                loop {
                    addr = match addr {
                        [c, rest @ ..] if unreserved(*c) || sub_delims(*c) || matches!(c, b':') => {
                            rest
                        }
                        [b']', rest @ ..] => break rest,
                        _ => return Err(Error::todo()),
                    }
                }
            }
            [c, rest @ ..] if matches!(c, b':' | b'0'..=b'9' | b'A'..=b'F') => {
                let mut ipv6 = rest;
                loop {
                    ipv6 = match ipv6 {
                        [b']', rest @ ..] => break rest,
                        // FIXME: implement "real" ipv6 parsing
                        [c, rest @ ..] if matches!(c, b'0'..=b'9' | b'A'..=b'F' | b':' | b'.') => {
                            rest
                        }
                        _ => return Err(Error::todo()),
                    }
                }
            }
            _ => return Err(Error::todo()),
        };
        match following {
            [b':', rest @ ..] => port(
                rest,
                scheme_sep,
                userinfo_sep,
                f(following).try_into().map_err(|_| Error::too_large())?,
                f,
            ),
            rest => {
                let path_start = f(rest).try_into().map_err(|_| Error::too_large())?;
                path(rest, scheme_sep, userinfo_sep, path_start, path_start, f)
            }
        }
    } else {
        loop {
            bytes = match bytes {
                [b, rest @ ..] if unreserved(*b) || sub_delims(*b) => rest,
                [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => rest,
                [b':', rest @ ..] => {
                    return port(
                        rest,
                        scheme_sep,
                        userinfo_sep,
                        f(bytes).try_into().map_err(|_| Error::too_large())?,
                        f,
                    )
                }
                [b'/', p @ ..] => {
                    let path_start = f(bytes).try_into().map_err(|_| Error::too_large())?;
                    return path(p, scheme_sep, userinfo_sep, path_start, path_start, f);
                }
                [b'?', p @ ..] => {
                    let query_sep = f(bytes);
                    let path_start = query_sep.try_into().map_err(|_| Error::too_large())?;
                    return query(
                        p,
                        scheme_sep,
                        userinfo_sep,
                        path_start,
                        path_start,
                        query_sep,
                        f,
                    );
                }
                [b'#', p @ ..] => {
                    let fragment_sep = f(bytes);
                    let path_start = fragment_sep.try_into().map_err(|_| Error::too_large())?;
                    return fragment(
                        p,
                        scheme_sep,
                        userinfo_sep,
                        path_start,
                        path_start,
                        fragment_sep,
                        fragment_sep,
                        f,
                    );
                }
                [] => {
                    let end = f(bytes);
                    let path_start = end.try_into().map_err(|_| Error::too_large())?;

                    return Ok(Uri {
                        scheme_sep,
                        userinfo_sep,
                        port_sep: path_start,
                        path_start,
                        query_sep: end,
                        fragment_sep: end,
                        data: (),
                    });
                }
                _ => return Err(Error::todo()),
            }
        }
    }
}

fn authority(
    mut bytes: &[u8],
    scheme_sep: u32,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    let mut last_colon = None;
    loop {
        bytes = match bytes {
            [d, rest @ ..] if digit(*d) => rest,
            [b, rest @ ..] if unreserved(*b) || sub_delims(*b) => {
                last_colon = None;
                rest
            }
            [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => {
                last_colon = None;
                rest
            }
            [b':', rest @ ..] => {
                last_colon = Some(f(bytes).try_into().map_err(|_| Error::too_large())?);
                rest
            }
            [b'@', rest @ ..] => {
                return host(
                    rest,
                    scheme_sep,
                    f(bytes).try_into().map_err(|_| Error::too_large())?,
                    f,
                )
            }
            [b'[', ..] => return host(bytes, scheme_sep, scheme_sep, f),
            [b'/', p @ ..] => {
                let path_start = f(bytes).try_into().map_err(|_| Error::too_large())?;
                return path(
                    p,
                    scheme_sep,
                    scheme_sep,
                    last_colon.unwrap_or(path_start),
                    path_start,
                    f,
                );
            }
            [b'?', p @ ..] => {
                let query_sep = f(bytes);
                let path_start = query_sep.try_into().map_err(|_| Error::too_large())?;
                return query(
                    p,
                    scheme_sep,
                    scheme_sep,
                    last_colon.unwrap_or(path_start),
                    path_start,
                    query_sep,
                    f,
                );
            }
            [b'#', p @ ..] => {
                let fragment_sep = f(bytes);
                let path_start = fragment_sep.try_into().map_err(|_| Error::too_large())?;
                return fragment(
                    p,
                    scheme_sep,
                    scheme_sep,
                    last_colon.unwrap_or(path_start),
                    path_start,
                    fragment_sep,
                    fragment_sep,
                    f,
                );
            }
            [] => {
                let end = f(bytes);
                let path_start = end.try_into().map_err(|_| Error::too_large())?;
                return Ok(Uri {
                    scheme_sep,
                    userinfo_sep: scheme_sep,
                    port_sep: last_colon.unwrap_or(path_start),
                    path_start,
                    query_sep: end,
                    fragment_sep: end,
                    data: (),
                });
            }
            _ => return Err(Error::todo()),
        }
    }
}
fn fragment(
    mut bytes: &[u8],
    scheme_sep: u32,
    userinfo_sep: u32,
    port_sep: u32,
    path_start: u32,
    query_sep: usize,
    fragment_sep: usize,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b, rest @ ..] if uncoded_pchar(*b) || matches!(b, b'/' | b'?') => rest,
            [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => rest,
            [] => {
                return Ok(Uri {
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    query_sep,
                    fragment_sep,
                    data: (),
                })
            }
            v => return Err(Error(Repr::Fragment(fragment_sep, f(bytes)))),
        }
    }
}
fn query(
    mut bytes: &[u8],
    scheme_sep: u32,
    userinfo_sep: u32,
    port_sep: u32,
    path_start: u32,
    query_sep: usize,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b, rest @ ..] if uncoded_pchar(*b) || matches!(b, b'/' | b'?') => rest,
            [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => rest,
            [b'#', rest @ ..] => {
                return fragment(
                    rest,
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    query_sep,
                    f(bytes),
                    f,
                )
            }
            [] => {
                return Ok(Uri {
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    query_sep,
                    fragment_sep: f(bytes),
                    data: (),
                })
            }
            _ => return Err(Error::todo()),
        }
    }
}
fn path(
    mut bytes: &[u8],
    scheme_sep: u32,
    userinfo_sep: u32,
    port_sep: u32,
    path_start: u32,
    f: impl Fn(&[u8]) -> usize,
) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b, rest @ ..] if uncoded_pchar(*b) || matches!(b, b'/') => rest,
            [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => rest,
            [b'?', rest @ ..] => {
                return query(
                    rest,
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    f(bytes),
                    f,
                )
            }
            [b'#', rest @ ..] => {
                return fragment(
                    rest,
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    f(bytes),
                    f(bytes),
                    f,
                )
            }
            [] => {
                return Ok(Uri {
                    scheme_sep,
                    userinfo_sep,
                    port_sep,
                    path_start,
                    query_sep: f(bytes),
                    fragment_sep: f(bytes),
                    data: (),
                })
            }
            _ => return Err(Error::todo()),
        }
    }
}
fn no_colon_segment(mut bytes: &[u8], f: impl Fn(&[u8]) -> usize) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b, rest @ ..] if unreserved(*b) || sub_delims(*b) || matches!(b, b'@') => rest,
            [b'%', a, b, rest @ ..] if hexdig(*a) && hexdig(*b) => rest,
            [b'/', rest @ ..] => return path(rest, 0, 0, 0, 0, f),
            [] => {
                return Ok(Uri {
                    scheme_sep: 0,
                    userinfo_sep: 0,
                    port_sep: 0,
                    path_start: 0,
                    query_sep: f(bytes),
                    fragment_sep: f(bytes),
                    data: (),
                })
            }
            _ => return Err(Error(Repr::NoColonSegment(f(bytes)))),
        }
    }
}
fn maybe_scheme(mut bytes: &[u8], f: impl Fn(&[u8]) -> usize) -> Result<Uri<()>, Error> {
    loop {
        bytes = match bytes {
            [b, rest @ ..] if scheme_char(*b) => rest,
            [b':', b'/', b'/', rest @ ..] => {
                return authority(
                    rest,
                    f(bytes).try_into().map_err(|_| Error::too_large())?,
                    f,
                )
            }
            [b':', rest @ ..] => {
                let scheme_sep = f(bytes).try_into().map_err(|_| Error::too_large())?;
                return path(
                    rest,
                    scheme_sep,
                    scheme_sep,
                    scheme_sep + 1,
                    scheme_sep + 1,
                    f,
                );
            }
            noscheme => return no_colon_segment(noscheme, f),
        }
    }
}
pub fn parse_bytes(bytes: &[u8]) -> Result<Uri<()>, Error> {
    let offset = |slice: &[u8]| slice.as_ptr() as usize - bytes.as_ptr() as usize;
    match bytes {
        [b'/', b'/', auth @ ..] => authority(auth, 0, offset),
        [b, maybescheme @ ..] if alpha(*b) => maybe_scheme(maybescheme, offset),
        noscheme => no_colon_segment(noscheme, offset),
    }
}

#[cfg(test)]
mod tests {
    use crate::Segment;

    use super::*;

    #[test]
    fn correct_parsing() {
        for &(text, expected) in &[
            ("foo.bar:", &[(Segment::Scheme, "foo.bar")][..]),
            (
                "https://docs.rs/uri",
                &[
                    (Segment::Scheme, "https"),
                    (Segment::Host, "docs.rs"),
                    (Segment::Path, "/uri"),
                ],
            ),
            (
                "https://google.com:80?whatif=ha&twelve=10",
                &[
                    (Segment::Scheme, "https"),
                    (Segment::Host, "google.com"),
                    (Segment::Port, "80"),
                    (Segment::Query, "whatif=ha&twelve=10"),
                ],
            ),
            (
                "magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a",
                &[
                    (Segment::Scheme, "magnet"),
                    (
                        Segment::Query,
                        "xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a",
                    ),
                ],
            ),
            (
                "https://user:password@localhost:8080/public/index.html?authorized=true#/private",
                &[
                    (Segment::Scheme, "https"),
                    (Segment::Userinfo, "user:password"),
                    (Segment::Host, "localhost"),
                    (Segment::Port, "8080"),
                    (Segment::Path, "/public/index.html"),
                    (Segment::Query, "authorized=true"),
                    (Segment::Fragment, "/private"),
                ],
            ),
            ("anything", &[(Segment::Path, "anything")]),
        ] {
            let uri = Uri::parse(text.as_bytes()).expect("valid URI to parse");
            for &(segment, expected) in expected {
                assert_eq!(&uri[segment], expected);
            }
            assert_eq!(uri.segments().collect::<Vec<_>>(), expected);
        }
    }
    #[test]
    fn invalid_uris() {
        for &(not_uri, reason) in &[
            (":9d283f", "minimum scheme length is 1"),
            ("A://@:/?##", "fragment must not contain #"),
            ("-https://github.com:6071", ""),
        ] {
            Uri::parse(not_uri).expect_err(reason);
        }
    }
}
