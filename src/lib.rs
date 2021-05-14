use core::convert::TryInto;
use core::{
    cmp, fmt, hash,
    ops::{self, Bound},
};

mod parser;

#[derive(Debug)]
pub struct Error(Repr);
#[derive(Debug)]
enum Repr {
    Fragment(usize, usize),
    NoColonSegment(usize),
    TooLarge,
    Todo,
}
impl Error {
    fn todo() -> Self {
        Self(Repr::Todo)
    }
    fn too_large() -> Self {
        Self(Repr::TooLarge)
    }
    pub fn within<B>(self, buffer: B) -> BadUri<B> {
        BadUri {
            error: self,
            buffer,
        }
    }
}
pub struct BadUri<B> {
    error: Error,
    buffer: B,
}
fn decode_utf8(b: &[u8]) -> Option<char> {
    core::str::from_utf8(b)
        .unwrap_or_else(|e| core::str::from_utf8(&b[..e.valid_up_to()]).unwrap())
        .chars()
        .next()
}
impl<B: Buffer> fmt::Display for BadUri<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error.0 {
            Repr::TooLarge => f.write_str("the authority was larger than 4GB"),
            Repr::Fragment(hash, err) => {
                let bytes = self.buffer.as_bytes();
                let context =
                    core::str::from_utf8(&bytes[hash.min(err.checked_sub(12).unwrap_or(0))..err])
                        .unwrap();

                let err = decode_utf8(&bytes[err..]).unwrap_or(core::char::REPLACEMENT_CHARACTER);
                write!(f, "expected fragment after {:?}, found {:?}", context, err)
            }
            Repr::NoColonSegment(err) => {
                let bytes = self.buffer.as_bytes();
                match &bytes[err..] {
                    [b':', ..] => write!(
                        f,
                        "invalid scheme {:?}",
                        core::str::from_utf8(&bytes[..err]).unwrap()
                    ),
                    non_path => {
                        write!(
                            f,
                            "expected path after {:?}, found {:?}",
                            core::str::from_utf8(&bytes[..err]).unwrap(),
                            decode_utf8(non_path).unwrap_or(core::char::REPLACEMENT_CHARACTER)
                        )
                    }
                }
            }
            Repr::Todo => write!(f, "idk"),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Repr::TooLarge => f.write_str("the authority was larger than 4GB"),
            Repr::Fragment(..) => f.write_str("invalid URI fragment"),
            Repr::NoColonSegment(..) => f.write_str("invalid URI path"),
            Repr::Todo => f.write_str("idk"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Represents the `URI-reference` ABNF rule
// TODO: Allow a `&[u8]` buffer (among others through a trait like stable_deref_trait::StableDeref)
/// A Uniform Resource Identifier
///
/// ## Representation
///
/// To
#[derive(Clone)]
pub struct Uri<B: ?Sized> {
    scheme_sep: u32,
    userinfo_sep: u32,
    port_sep: u32,
    path_start: u32,
    query_sep: usize,
    fragment_sep: usize,

    data: B,
}
mod private {
    pub trait Sealed {}
    impl Sealed for Box<[u8]> {}
    impl Sealed for [u8] {}
    impl Sealed for str {}
    impl Sealed for String {}
    impl<T: ?Sized + Sealed> Sealed for &'_ T {}
}
pub unsafe trait Buffer: private::Sealed {
    fn as_bytes(&self) -> &[u8];
}
#[cfg(feature = "std")]
unsafe impl Buffer for Box<[u8]> {
    fn as_bytes(&self) -> &[u8] {
        &**self
    }
}
unsafe impl Buffer for [u8] {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}
unsafe impl Buffer for str {
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}
unsafe impl Buffer for String {
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}
unsafe impl<T: ?Sized + Buffer> Buffer for &'_ T {
    fn as_bytes(&self) -> &[u8] {
        (*self).as_bytes()
    }
}

impl<B: Buffer> Uri<B> {
    pub fn parse(data: B) -> Result<Self, (B, Error)> {
        match parser::parse_bytes(data.as_bytes()) {
            Ok(Uri {
                scheme_sep,
                userinfo_sep,
                port_sep,
                path_start,
                query_sep,
                fragment_sep,
                ..
            }) => Ok(Uri {
                scheme_sep,
                userinfo_sep,
                port_sep,
                path_start,
                query_sep,
                fragment_sep,
                data,
            }),
            Err(e) => Err((data, e)),
        }
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.data.as_bytes()).unwrap()
    }
    pub fn scheme(&self) -> Option<&str> {
        if self.scheme_sep != 0 {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Scheme)..self.end_of(Segment::Scheme))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn authority(&self) -> Option<&str> {
        if self.path_start > self.scheme_sep + 1 {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Userinfo)..self.end_of(Segment::Port))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn path(&self) -> &str {
        self.as_str()
            .get(self.start_of(Segment::Path)..self.end_of(Segment::Path))
            .unwrap()
    }
    pub fn query(&self) -> Option<&str> {
        if self.query_sep != self.fragment_sep {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Query)..self.end_of(Segment::Query))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn fragment(&self) -> Option<&str> {
        if self.fragment_sep != self.data.as_bytes().len() {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Fragment)..self.end_of(Segment::Fragment))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn userinfo(&self) -> Option<&str> {
        if self.userinfo_sep != self.scheme_sep {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Userinfo)..self.end_of(Segment::Userinfo))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn port(&self) -> Option<&str> {
        if self.port_sep != self.path_start {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Port)..self.end_of(Segment::Port))
                    .unwrap(),
            )
        } else {
            None
        }
    }
    pub fn host(&self) -> Option<&str> {
        if self.path_start
            != if self.scheme_sep == 0 {
                0
            } else {
                self.scheme_sep + 1
            }
        {
            Some(
                self.as_str()
                    .get(self.start_of(Segment::Host)..self.end_of(Segment::Host))
                    .unwrap(),
            )
        } else {
            None
        }
    }
}
impl<B> Uri<B> {
    pub fn into_inner(self) -> B {
        self.data
    }
}
///
///
/// ```asciidoc
/// https://user:password@localhost:8080/public/index.html?authorized=true#/private
/// ^----   ^------------ ^-------- ^--- ^---------------- ^-------------- ^-------
/// scheme  userinfo      host      port path              query           fragment
/// ```
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Segment {
    Scheme,
    Userinfo,
    Host,
    Port,
    Path,
    Query,
    Fragment,
}
impl<B: Buffer> ops::Index<Segment> for Uri<B> {
    type Output = str;
    fn index(&self, index: Segment) -> &Self::Output {
        &self.as_str()[self.start_of(index)..self.end_of(index)]
    }
}
impl<B: Buffer, R: core::ops::RangeBounds<Segment>> ops::Index<R> for Uri<B> {
    type Output = str;
    fn index(&self, index: R) -> &Self::Output {
        let s = self.as_str();
        &s[match index.start_bound() {
            Bound::Unbounded => 0,
            Bound::Excluded(seg) => self.end_of(*seg),
            Bound::Included(seg) => self.start_of(*seg),
        }..match index.end_bound() {
            Bound::Unbounded => s.len(),
            Bound::Excluded(seg) => self.start_of(*seg),
            Bound::Included(seg) => self.end_of(*seg),
        }]
    }
}
fn as_usize(n: u32) -> usize {
    n.try_into().unwrap()
}
impl<B: Buffer> Uri<B> {
    #[inline]
    fn start_of(&self, section: Segment) -> usize {
        match section {
            Segment::Scheme => 0,
            Segment::Userinfo => {
                as_usize(self.scheme_sep) + if self.scheme_sep != 0 { 3 } else { 2 }
            }
            Segment::Host => {
                if self.userinfo_sep != self.scheme_sep {
                    as_usize(self.userinfo_sep) + 1
                } else {
                    self.start_of(Segment::Userinfo)
                }
            }
            Segment::Port => as_usize(self.port_sep) + 1usize,
            Segment::Path => as_usize(self.path_start),
            Segment::Query => self.query_sep + 1,
            Segment::Fragment => self.fragment_sep + 1,
        }
    }
    #[inline]
    fn end_of(&self, section: Segment) -> usize {
        match section {
            Segment::Scheme => as_usize(self.scheme_sep),
            Segment::Userinfo => as_usize(self.userinfo_sep),
            Segment::Host => as_usize(self.port_sep),
            Segment::Port => as_usize(self.path_start),
            Segment::Path => self.query_sep,
            Segment::Query => self.fragment_sep,
            Segment::Fragment => self.data.as_bytes().len(),
        }
    }
    #[cfg(test)]
    fn segments(&self) -> impl Iterator<Item = (Segment, &str)> {
        vec![
            self.scheme().map(|p| (Segment::Scheme, p)),
            self.userinfo().map(|p| (Segment::Userinfo, p)),
            self.host().map(|p| (Segment::Host, p)),
            self.port().map(|p| (Segment::Port, p)),
            Some((Segment::Path, self.path())).filter(|(_, p)| p.len() != 0),
            self.query().map(|p| (Segment::Query, p)),
            self.fragment().map(|p| (Segment::Fragment, p)),
        ]
        .into_iter()
        .flatten()
    }
}

impl<B: Buffer> fmt::Display for Uri<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<B: Buffer> fmt::Debug for Uri<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Uri(")?;
        let mut need_whitespace = false;
        if let Some(scheme) = self.scheme() {
            fmt::Debug::fmt(scheme, f)?;
            f.write_str(" :")?;
            need_whitespace = true;
        }
        if self.authority().is_some() {
            f.write_str("// ")?;
            if let Some(userinfo) = self.userinfo() {
                fmt::Debug::fmt(userinfo, f)?;
                f.write_str(" @ ")?;
            }
            let host = self.host().unwrap();
            fmt::Debug::fmt(host, f)?;
            if let Some(port) = self.port() {
                f.write_str(" : ")?;
                fmt::Debug::fmt(port, f)?;
            }
            need_whitespace = true;
        }
        let path = self.path();
        if !path.is_empty() {
            if need_whitespace {
                f.write_str(" ")?;
            }
            fmt::Debug::fmt(path, f)?;
            need_whitespace = true;
        }
        if let Some(query) = self.query() {
            if need_whitespace {
                f.write_str(" ")?;
            }
            f.write_str("? ")?;
            fmt::Debug::fmt(query, f)?;
            need_whitespace = true;
        }
        if let Some(fragment) = self.fragment() {
            if need_whitespace {
                f.write_str(" ")?;
            }
            f.write_str("# ")?;
            fmt::Debug::fmt(fragment, f)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl<B: Buffer> AsRef<str> for Uri<B> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// Normalized comparisons
impl<B: Buffer> cmp::PartialEq for Uri<B> {
    fn eq(&self, _: &Self) -> bool {
        unimplemented!()
    }
}
impl<B: Buffer> cmp::Eq for Uri<B> {}
impl<B: Buffer> cmp::PartialOrd for Uri<B> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<B: Buffer> cmp::Ord for Uri<B> {
    fn cmp(&self, _: &Self) -> cmp::Ordering {
        unimplemented!()
    }
}
impl<B: Buffer> hash::Hash for Uri<B> {
    fn hash<H: hash::Hasher>(&self, _: &mut H) {
        unimplemented!()
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::*;

    impl<'de, B: Deserialize<'de> + Buffer> Deserialize<'de> for Uri<B> {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Uri::parse(T::deserialize(deserializer)?).map_err(|(s, _)| {
                de::Error::invalid_value(de::Unexpected::Str(s.as_ref()), &"a URI")
            })
        }
    }
    impl<B: Serialize> Serialize for Uri<B> {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.data.serialize(serializer)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{Segment, Uri};
    #[test]
    fn segment_ranges() {
        assert_eq!(
            &Uri::parse("//plecra@github.com/Plecra/uri?all_commits=true#darkmode").unwrap()
                [Segment::Path..],
            "/Plecra/uri?all_commits=true#darkmode"
        );
        assert_eq!(
            &Uri::parse("magnet:?xs=blah").unwrap()[..=Segment::Path],
            "magnet:"
        );
    }
}
