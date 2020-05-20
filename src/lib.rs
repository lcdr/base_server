pub mod listeners;
pub mod server;
mod tcpudp;
#[cfg(feature="tls")] mod tls;

#[cfg(feature="tls")] use std::sync::Arc;

#[cfg(feature="tls")]      pub type TlsConfig = Arc<rustls::ServerConfig>;
#[cfg(not(feature="tls"))] pub type TlsConfig = ();

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
	pub db: DbConf,
	pub tls: TlsConf,
}

#[derive(Deserialize)]
pub struct DbConf {
	pub path: String,
}

#[derive(Deserialize)]
pub struct TlsConf {
	#[cfg(feature="tls")]
	cert_path: String,
	#[cfg(feature="tls")]
	key_path: String,
}

#[cfg(feature="tls")]
pub fn create_tls_config(conf: TlsConf) -> TlsConfig {
	let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());

	let certfile = std::fs::File::open(conf.cert_path).expect("cannot open certificate file");
	let mut reader = std::io::BufReader::new(certfile);
	let certs = rustls::internal::pemfile::certs(&mut reader).unwrap();

	let keyfile = std::fs::File::open(conf.key_path).expect("cannot open key file");
	let mut reader = std::io::BufReader::new(keyfile);
	let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader).expect("file contains invalid pkcs8 private key (encrypted keys not supported)");

	config.set_single_cert(certs, keys[0].clone()).unwrap();
	Arc::new(config)
}

#[cfg(not(feature="tls"))]
pub fn create_tls_config(_conf: TlsConf) -> TlsConfig {
	()
}

pub fn load_config() -> Config {
	let mut exe_path = std::env::current_exe().expect("program location unknown");
	exe_path.pop();
	exe_path.push("config.toml");
	let config = std::fs::read_to_string(exe_path).expect("cannot open config file config.toml");
	let config: Config = toml::from_str(&config).expect("config file parsing error");

	config
}
