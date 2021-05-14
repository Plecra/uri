#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
// mod uriparser {
//     include!(concat!(env!("OUT_DIR"), "bindings.rs"));
// }
#[derive(Clone, Copy)]
struct Ascii<'a>(&'a [u8]);
impl core::fmt::Debug for Ascii<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.as_str().fmt(f)
    }
}
impl<'a> arbitrary::Arbitrary<'a> for Ascii<'a> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let size = u.arbitrary_len::<u8>()?;
        u.bytes(u.peek_bytes(size).unwrap().iter().position(|&b| b >= 128).unwrap_or(size)).map(Self)
    }
    fn arbitrary_take_rest(u: arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.take_rest();
        if bytes.iter().any(|&b| b >= 128) {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Ok(Self(bytes))
    }

    #[inline]
    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and(<usize as arbitrary::Arbitrary>::size_hint(depth), (0, None))
    }
}
impl<'a> Ascii<'a> {
    fn as_str(&self) -> &'a str {
        unsafe {
            core::str::from_utf8_unchecked(self.0)
        }
    }
}
// #[derive(arbitrary::Arbitrary)]
// struct Authority<'a> {
//     userinfo: Option<Ascii<'a>>,
//     host: Ascii<'a>,
//     port: Option<Ascii<'a>>,
// }
// #[derive(arbitrary::Arbitrary)]
// struct Uri<'a> {
//     scheme: Option<Ascii<'a>>,
//     authority: Option<Authority<'a>>,
//     path: Ascii<'a>,
//     query: Option<Ascii<'a>>,
//     fragment: Option<Ascii<'a>>,
// }
// impl core::fmt::Debug for Uri<'_> {
//     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//         self.to_string().fmt(f)
//     }
// }
// impl core::fmt::Display for Uri<'_> {
//     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//         use core::fmt::Write;
//         if let Some(scheme) = self.scheme {
//             f.write_str(scheme.as_str())?;
//             f.write_char(':')?;
//         }
//         if let Some(auth) = &self.authority {
//             f.write_char('/')?;
//             f.write_char('/')?;
//             if let Some(ui) = auth.userinfo {
//                 f.write_str(ui.as_str())?;
//                 f.write_char('@')?;
//             }
//             f.write_str(auth.host.as_str())?;
//             if let Some(port) = auth.port {
//                 f.write_char(':')?;
//                 f.write_str(port.as_str())?;
//             }
//             if !self.path.as_str().is_empty() {
//                 f.write_char('/')?;
//             }
//         }
//         f.write_str(self.path.as_str())?;
//         if let Some(q) = self.query {
//             f.write_char('?')?;
//             f.write_str(q.as_str())?;
//         }
//         if let Some(fragment) = self.fragment {
//             f.write_char('#')?;
//             f.write_str(fragment.as_str())?;
//         }
//         Ok(())
//     }
// }

fuzz_target!(|data: Ascii| {
    let data = data.as_str().as_bytes();
    if let Ok(uri) = uri::Uri::parse(data) {
        if let Ok(alt_uri) = uriparser::Uri::parse(data) {
            assert_eq!(uri.scheme(), alt_uri.scheme());
            assert_eq!(uri.userinfo(), alt_uri.userinfo());
            assert_eq!(match uri.host().map(|b| b.as_bytes()) {
                // uriparser strips the delimiters from IP literals
                Some([b'[', literal @ .., b']']) => Some(literal),
                other => other
            }, alt_uri.host().map(|h| h.as_bytes()));
            assert_eq!(uri.port(), alt_uri.port());
            assert_eq!(&alt_uri.path(), uri.path());
            assert_eq!(uri.query(), alt_uri.query());
            assert_eq!(uri.fragment(), alt_uri.fragment());
        }
        // // Exceptions for quirky features in `url`
        // if uri.scheme().map_or(false, |s| ["ftp", "file", "http", "https", "ws", "wss"].contains(&s)) // "special schemes" have different parsing rules
        // // FIXME: we need to be testing path-like uris
        // || uri.path().starts_with("/") // path-like urls are normalized
        // {
        //     // ignore "special schemes" bc they confuse the fuzzer
        //     return;
        // }
        // if let Ok(url) = url::Url::parse(core::str::from_utf8(data).unwrap()) {
        //     assert_eq!(uri.scheme().unwrap_or("").to_lowercase(), url.scheme());
        //     let userinfo = uri.userinfo();
        //     let username = url.username();
        //     assert_eq!(uri.userinfo().map_or("", |ui| &ui[..username.len()]), username);
        //     let password = url.password();
        //     assert_eq!(uri.userinfo().and_then(|ui| password.map(|p| &ui[ui.len() - p.len()..])), password);
        //     assert_eq!(uri.host(), url.host_str().or_else(|| Some("").filter(|_| url.has_authority())));
        //     // assert_eq!(uri.port(), url._);
        //     assert_eq!(uri.path(), url.path());
        //     assert_eq!(uri.query(), url.query());
        //     assert_eq!(uri.fragment(), url.fragment());
        // }

    }
});
