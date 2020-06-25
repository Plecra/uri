pub struct Error {}

impl fmt::Display for Error {}
impl fmt::Debug for Error {}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

type Result<T, E = Error> = core::result::Result<T, E>;

/// Marker trait for types that a `Uri` can contain
///
/// The guarantees this trait makes are not yet defined, so 
/// there is currently **no** safe way to implement it.
// The gist is just that implementers will return the
// same slice so long as they're not mutated
pub unsafe trait StableStrRef: AsRef<str> {}

unsafe impl<T: StableStrRef> StableStrRef for &'_ T {}
unsafe impl StableStrRef for str {}
unsafe impl StableStrRef for String {}

/// A Uri as defined by [RFC 3986]
///
///
/// [RFC 3986]: https://tools.ietf.org/html/rfc3986
// Represents the `URI-reference` ABNF rule
pub struct Uri<T: StableStrRef> {
    data: T,
}

impl<T: StableStrRef> Uri<T> {
    fn parse(data: T) -> Result<Self> {
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
    
    fn into_inner(self) -> T {
        self.data
    }
}

impl<T: StableStrRef> fmt::Display for Uri<T> {} // Uri("https://github.com/Plecra")
impl<T: StableStrRef> fmt::Debug for Uri<T> {} // Uri("https" : // "github.com" "/Plecra")
impl<T: StableStrRef> AsRef<str> for Uri<T> {} // "https://github.com/Plecra"

// Normalized comparisons
impl<T: StableStrRef> PartialEq for Uri<T> {}
impl<T: StableStrRef> Eq for Uri<T> {}
impl<T: StableStrRef> PartialOrd for Uri<T> {}
impl<T: StableStrRef> Ord for Uri<T> {}
impl<T: StableStrRef> Hash for Uri<T> {}

impl<T: StableStrRef + Clone> Clone for Uri<T> {}
impl<T: StableStrRef + Sync> Sync for Uri<T> {}
impl<T: StableStrRef + Send> Send for Uri<T> {}
impl<T: StableStrRef + Default> Default for Uri<T> {}

#[cfg(feature = "serde")]
impl<'de, T: StableStrRef> de::Deserialize<'de> for Uri<T> {}
#[cfg(feature = "serde")]
impl<T: StableStrRef> ser::Serialize for Uri<T> {}
