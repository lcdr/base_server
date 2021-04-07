//! Message listeners responsible for the behavior of the server in response to incoming messages.
use lu_packets;

use std::io::Result as Res;
use std::net::{IpAddr, Ipv4Addr};

use lu_packets::{
	common::ServiceId,
	raknet::SystemAddress,
	raknet::client::{ConnectedPong, ConnectionRequestAccepted},
	general::client::Handshake as OutHandshake,
	raknet::server::{ConnectionRequest, InternalPing},
	general::server::{Handshake as IncHandshake},
};

use crate::server::Context as C;

use endio::{Deserialize, Serialize};
use endio::LittleEndian as LE;

/// Sends back a pong with the same timestamp.
pub fn on_internal_ping<I, O>(ping: &InternalPing, ctx: &mut C<I, O>) -> Res<()>
	where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>>,
	O: From<ConnectedPong> {
	ctx.send(ConnectedPong { ping_send_time: ping.send_time })
}

/// Helper function to convert IPv6 addresses to equivalent IPv4 addresses if possible, or panic otherwise.
fn get_ipv4(ip: IpAddr) -> Ipv4Addr {
	match ip {
		IpAddr::V4(ip) => ip,
		IpAddr::V6(ip) => {
			if ip.is_loopback() {
				Ipv4Addr::LOCALHOST
			} else {
				panic!();
			}
		}
	}
}

/// Sends back a connection request accepted message with local address and remote address.
pub fn on_conn_req<I, O>(conn_req: &ConnectionRequest, ctx: &mut C<I, O>) -> Res<()>
	where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>>,
		O: From<ConnectionRequestAccepted> {
	if *conn_req.password != b"3.25 ND1"[..] {
		ctx.close_conn();
		return Ok(());
	};
	let peer_addr = ctx.peer_addr().unwrap();
	let peer_ip = get_ipv4(peer_addr.ip());
	let local_addr = ctx.local_addr().unwrap();
	let local_ip = get_ipv4(local_addr.ip());
	let message = ConnectionRequestAccepted {
		peer_addr : SystemAddress { ip: peer_ip, port: peer_addr.port() },
		local_addr : SystemAddress { ip: local_ip, port: local_addr.port() },
	};
	ctx.send(message)
}

/**
	Checks for network version and service ID, closing the connection if either doesn't match, otherwise sends back our own network version and service ID.
*/
pub fn on_handshake<I, O>(inc_handshake: &IncHandshake, ctx: &mut C<I, O>, service_id: ServiceId) -> Res<()>
	where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>>,
		O: From<OutHandshake> {
	const NETWORK_VERSION: u32 = 171022;

	if inc_handshake.network_version != NETWORK_VERSION {
		println!("wrong network version {}", inc_handshake.network_version);
		ctx.close_conn();
		return Ok(());
	}
	if inc_handshake.service_id != ServiceId::Client {
		println!("wrong service id {:?}", inc_handshake.service_id);
		ctx.close_conn();
		return Ok(());
	}
	let message = OutHandshake {
		network_version: NETWORK_VERSION,
		service_id,
	};
	ctx.send(message)
}
