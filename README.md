# uri

[![Crates.io badge](https://meritbadge.herokuapp.com/uri)](https://crates.io/crates/uri)

An [RFC 3986] validating parser. As efficient as I can make it

### `no_std` support

By disabling the default `std` feature, this crate will behave normally in a `no_std` context:

```toml
[dependencies]
uri = { version = "1", default-features = false }
```


[RFC 3986]: https://tools.ietf.org/html/rfc3986