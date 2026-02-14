use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

use crate::cipher::RsaCipher;
use crate::core::control::controller::{Controller, VntContext};
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
        controller: Controller,
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
    pub async fn leave(&self, context: VntContext) {
        self.server.leave(context).await;
    }
    async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Result<Option<NetPacket<Vec<u8>>>> {
        if net_packet.is_gateway() {
            self.server
                .handle(context, net_packet, addr, tcp_sender)
                .await
        } else {
            self.client.handle(context, net_packet, addr).await?;
            Ok(None)
        }
    }
}

impl PacketHandler {
    pub fn new(
        controller: Controller,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        Self {
            dispatcher: PacketDispatcher::new(controller, config, rsa_cipher, udp),
        }
    }
    pub async fn leave(&self, context: VntContext) {
        self.dispatcher.leave(context).await;
    }
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        context: &mut VntContext,
        net_packet: NetPacket<B>,
        addr: SocketAddr,
        tcp_sender: &Option<Sender<Vec<u8>>>,
    ) -> Option<NetPacket<Vec<u8>>> {
        self.dispatcher
            .handle(context, net_packet, addr, tcp_sender)
            .await
            .unwrap_or_else(|e| {
                log::error!("addr={},{:?}", addr, e);
                None
            })
    }
}
