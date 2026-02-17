#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use crate::cipher::RsaCipher;
use crate::core::control::controller::{Controller, SessionNetworkInfo, VntSession};
use crate::error::*;
use crate::protocol::NetPacket;
use crate::ConfigInfo;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct ClientPacketHandler {
    controller: Arc<Controller>,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
    udp: Arc<UdpSocket>,
}

impl ClientPacketHandler {
    pub fn new(
        controller: Arc<Controller>,
        config: ConfigInfo,
        rsa_cipher: Option<RsaCipher>,
        udp: Arc<UdpSocket>,
    ) -> Self {
        Self {
            controller,
            config,
            rsa_cipher,
            udp,
        }
    }
}

impl ClientPacketHandler {
    pub async fn handle<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        session: &VntSession,
        net_packet: NetPacket<B>,
    ) -> Result<()> {
        if let Some(network_info) = session.network_info() {
            self.handle0(network_info, net_packet).await
        } else {
            Err(Error::Disconnect)?
        }
    }
}

impl ClientPacketHandler {
    /// 转发到目标地址
    async fn handle0<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        network_info: &SessionNetworkInfo,
        mut net_packet: NetPacket<B>,
    ) -> Result<()> {
        if net_packet.incr_ttl() > 1 {
            if self.config.check_finger {
                let finger = crate::cipher::Finger::new(&network_info.group);
                finger.check_finger(&net_packet)?;
            }
            let destination = net_packet.destination();
            if destination.is_broadcast() || self.config.broadcast == destination {
                //处理广播
                self.broadcast(network_info, net_packet).await;
            } else {
                let is_encrypt = net_packet.is_encrypt();
                let source_ip = u32::from(net_packet.source());
                let rs = self
                    .controller
                    .with_network_read(&network_info.group, |group_network_info| {
                        group_network_info
                            .clients
                            .get(&destination.into())
                            .filter(|v| {
                                v.wireguard.is_none()
                                    && v.online
                                    && v.client_secret == is_encrypt
                                    && v.virtual_ip != source_ip
                            })
                            .map(|v| {
                                (
                                    v.address,
                                    self.controller
                                        .get_tcp_sender(&network_info.group, v.virtual_ip),
                                )
                            })
                    })
                    .ok_or(Error::Disconnect)?;
                if let Some((peer_addr, peer_tcp_sender)) = rs {
                    send_one(&self.udp, peer_addr, peer_tcp_sender, &net_packet).await;
                }
            }
        }
        Ok(())
    }

    async fn broadcast<B: AsRef<[u8]>>(
        &self,
        network_info: &SessionNetworkInfo,
        net_packet: NetPacket<B>,
    ) {
        let Some(list) = self
            .controller
            .with_network_read(&network_info.group, |group_network_info| {
                let is_encrypt = net_packet.is_encrypt();
                let source_ip = u32::from(net_packet.source());
                group_network_info
                    .clients
                    .values()
                    .filter(|v| {
                        v.wireguard.is_none()
                            && v.online
                            && v.client_secret == is_encrypt
                            && v.virtual_ip != source_ip
                    })
                    .map(|v| {
                        (
                            v.address,
                            self.controller.get_tcp_sender(&network_info.group, v.virtual_ip),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        else {
            return;
        };
        for (peer_addr, peer_tcp_sender) in list {
            send_one(&self.udp, peer_addr, peer_tcp_sender, &net_packet).await;
        }
    }
}

async fn send_one<B: AsRef<[u8]>>(
    udp_socket: &UdpSocket,
    peer_addr: SocketAddr,
    peer_tcp_sender: Option<Sender<Vec<u8>>>,
    net_packet: &NetPacket<B>,
) {
    if let Some(sender) = &peer_tcp_sender {
        let _ = sender.send(net_packet.buffer().to_vec()).await;
    } else {
        let _ = udp_socket.send_to(net_packet.buffer(), peer_addr).await;
    }
}
