use ascii::AsciiStr;
use core::{cmp, fmt, hash};

pub enum Error {}

impl fmt::Display for Error {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
        match *self {}
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result {
        match *self {}
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Marker trait for types that a `Uri` can contain
///
/// The guarantees this trait makes are not yet defined, so
/// there is currently **no** safe way to implement it.
// The gist is just that implementers will return the
// same slice so long as they're not mutated
pub unsafe trait StableAsciiStrRef: AsRef<AsciiStr> {}

unsafe impl<T: StableAsciiStrRef> StableAsciiStrRef for &'_ T {}

unsafe impl StableAsciiStrRef for AsciiStr {}

#[cfg(feature = "std")]
unsafe impl StableAsciiStrRef for ascii::AsciiString {}

// Represents the `URI-reference` ABNF rule
pub struct Uri<T: StableAsciiStrRef> {
    data: T,
}

impl<T: StableAsciiStrRef> Uri<T> {
    pub fn parse(_: T) -> Result<Self, (T, Error)> {
        unimplemented!()
    }

    pub fn scheme(&self) -> Option<&str> {
        unimplemented!()
    }
    pub fn authority(&self) -> Option<&str> {
        unimplemented!()
    }
    pub fn path(&self) -> &str {
        unimplemented!()
    }
    pub fn query(&self) -> Option<&str> {
        unimplemented!()
    }
    pub fn fragment(&self) -> Option<&str> {
        unimplemented!()
    }

    // Components of Uri::authority
    pub fn userinfo(&self) -> Option<&str> {
        unimplemented!()
    }
    pub fn port(&self) -> Option<&str> {
        unimplemented!()
    }
    pub fn host(&self) -> Option<&str> {
        unimplemented!()
    }

    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: StableAsciiStrRef> fmt::Display for Uri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl<T: StableAsciiStrRef> fmt::Debug for Uri<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Uri(")?;
        if let Some(scheme) = self.scheme() {
            fmt::Debug::fmt(scheme, f)?;
            f.write_str(" : ")?;
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
            f.write_str(" ")?;
        }
        fmt::Debug::fmt(self.path(), f)?;
        if let Some(query) = self.query() {
            f.write_str(" ? ")?;
            fmt::Debug::fmt(query, f)?;
        }
        if let Some(fragment) = self.fragment() {
            f.write_str(" # ")?;
            fmt::Debug::fmt(fragment, f)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

impl<T: StableAsciiStrRef> AsRef<[u8]> for Uri<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref().as_bytes()
    }
}
impl<T: StableAsciiStrRef> AsRef<AsciiStr> for Uri<T> {
    fn as_ref(&self) -> &AsciiStr {
        self.data.as_ref()
    }
}
impl<T: StableAsciiStrRef> AsRef<str> for Uri<T> {
    fn as_ref(&self) -> &str {
        self.data.as_ref().as_str()
    }
}

// Normalized comparisons
impl<T: StableAsciiStrRef> cmp::PartialEq for Uri<T> {
    fn eq(&self, _: &Self) -> bool {
        unimplemented!()
    }
}
impl<T: StableAsciiStrRef> cmp::Eq for Uri<T> {}
impl<T: StableAsciiStrRef> cmp::PartialOrd for Uri<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: StableAsciiStrRef> cmp::Ord for Uri<T> {
    fn cmp(&self, _: &Self) -> cmp::Ordering {
        unimplemented!()
    }
}
impl<T: StableAsciiStrRef> hash::Hash for Uri<T> {
    fn hash<H: hash::Hasher>(&self, _: &mut H) {
        unimplemented!()
    }
}

impl<T: StableAsciiStrRef + Clone> Clone for Uri<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}
unsafe impl<T: StableAsciiStrRef + Sync> Sync for Uri<T> {}
unsafe impl<T: StableAsciiStrRef + Send> Send for Uri<T> {}

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::*;

    impl<'de, T: StableAsciiStrRef + Deserialize<'de>> Deserialize<'de> for Uri<T> {
        fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Uri::parse(T::deserialize(deserializer)?).map_err(|(s, _)| {
                use de::Error;
                D::Error::invalid_value(de::Unexpected::Str(s.as_ref()), &"a URI")
            })
        }
    }
    impl<T: StableAsciiStrRef + Serialize> Serialize for Uri<T> {
        fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.data.serialize(serializer)
        }
    }
}
