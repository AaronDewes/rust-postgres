use futures_util::FutureExt;
use rustls::RootCertStore;
use rustls_pemfile::{read_one, Item};
use std::fs::File;
use std::io::{self, BufReader};
use tokio::net::TcpStream;
use tokio_postgres::tls::TlsConnect;

use super::*;

fn load_cert(filename: &str) -> io::Result<RootCertStore> {
    let certfile = File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let Item::X509Certificate(cert) = read_one(&mut reader).unwrap().unwrap() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid certificate",
        ))?;
    };
    let mut root_store = RootCertStore::empty();
    root_store.add(cert).unwrap();
    Ok(root_store)
}

async fn smoke_test<T>(s: &str, tls: T)
where
    T: TlsConnect<TcpStream>,
    T::Stream: 'static + Send,
{
    let stream = TcpStream::connect("127.0.0.1:5433").await.unwrap();

    let builder = s.parse::<tokio_postgres::Config>().unwrap();
    let (client, connection) = builder.connect_raw(stream, tls).await.unwrap();

    let connection = connection.map(|r| r.unwrap());
    tokio::spawn(connection);

    let stmt = client.prepare("SELECT $1::INT4").await.unwrap();
    let rows = client.query(&stmt, &[&1i32]).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i32>(0), 1);
}

#[tokio::test]
async fn require() {
    // Load ../test/server.crt into a Rustls client config
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    smoke_test(
        "user=ssl_user dbname=postgres sslmode=require",
        TlsConnector::new(config, "localhost").unwrap(),
    )
    .await;
}

#[tokio::test]
async fn prefer() {
    // Load ../test/server.crt into a Rustls client config
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    smoke_test(
        "user=ssl_user dbname=postgres",
        TlsConnector::new(config, "localhost").unwrap(),
    )
    .await;
}

#[tokio::test]
async fn scram_user() {
    // Load ../test/server.crt into a Rustls client config
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    smoke_test(
        "user=scram_user password=password dbname=postgres sslmode=require",
        TlsConnector::new(config, "localhost").unwrap(),
    )
    .await;
}

#[tokio::test]
async fn require_channel_binding_err() {
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::new(config, "localhost").unwrap();

    let stream = TcpStream::connect("127.0.0.1:5433").await.unwrap();
    let builder = "user=pass_user password=password dbname=postgres channel_binding=require"
        .parse::<tokio_postgres::Config>()
        .unwrap();
    builder.connect_raw(stream, connector).await.err().unwrap();
}

#[tokio::test]
async fn require_channel_binding_ok() {
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    smoke_test(
        "user=scram_user password=password dbname=postgres channel_binding=require",
        TlsConnector::new(config, "localhost").unwrap(),
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "runtime")]
async fn runtime() {
    // Load ../test/server.crt into a Rustls client config
    let root_store = load_cert("../test/server.crt").unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = MakeTlsConnector::new(config);

    let (client, connection) = tokio_postgres::connect(
        "host=localhost port=5433 user=postgres sslmode=require",
        connector,
    )
    .await
    .unwrap();
    let connection = connection.map(|r| r.unwrap());
    tokio::spawn(connection);

    let stmt = client.prepare("SELECT $1::INT4").await.unwrap();
    let rows = client.query(&stmt, &[&1i32]).await.unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i32>(0), 1);
}
