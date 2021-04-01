fn main() {
    let uri = uri::Uri::parse("https://user:password@localhost:8080/public/index.html?authorized=true#/private".as_bytes()).unwrap();
    println!("{}", uri.path());
}
