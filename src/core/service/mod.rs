use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

use crate::cipher::RsaCipher;
use crate::core::control::controller::{Controller, VntSession};
use crate::core::service::client::ClientPacketHandler;
use crate::core::service::server::ServerPacketHandler;
use crate::error::*;
use crate::protocol::NetPacket;
use crate::ConfigInfo;

pub mod client;
pub mod server;

#[derive(Clone)]
pub struct PacketHandler {
    dispatcher: PacketDispatcher,
}

#[derive(Clone)]
struct PacketDispatcher {
    client: ClientPacketHandler,
    server: ServerPacketHandler,
}

impl PacketDispatcher {
    pub fn new(
        controller: Arc<Controller>,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        let client = ClientPacketHandler::new(
            controller.clone(),
            config.clone(),
            rsa_cipher.clone(),
            udp.clone(),
        );
        let server =
            ServerPacketHandler::new(controller.clone(), config.clone(), rsa_cipher.clone(), udp);
        Self { client, server }
    }
    pub async fn leave(&self, session: VntSession) {
        self.server.leave(session).await;
    }
    async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        session: &mut VntSession,
        net_packet: NetPacket<B>,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        if net_packet.is_gateway() {
            self.server.handle(session, net_packet, tcp_sender).await
        } else {
            self.client.handle(session, net_packet).await?;
            Ok(None)
        }
    }
}

impl PacketHandler {
    pub fn new(
        controller: Arc<Controller>,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        Self {
            dispatcher: PacketDispatcher::new(controller, config, rsa_cipher, udp),
        }
    }
    pub async fn leave(&self, session: VntSession) {
        self.dispatcher.leave(session).await;
    }
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        session: &mut VntSession,
        net_packet: NetPacket<B>,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Option<NetPacket<Vec<u8>>> {
        self.dispatcher
            .handle(session, net_packet, tcp_sender)
            .await
            .unwrap_or_else(|e| {
                log::error!("addr={},{:?}", session.address(), e);
                None
            })
    }
}
