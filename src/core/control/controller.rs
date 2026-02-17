use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use crate::cipher::Aes256GcmCipher;
use crate::core::control::expire_map::ExpireMap;
use crate::core::entity::{NetworkInfo, SimpleClientInfo, WireGuardConfig};

pub struct VntSession {
    network_info: Option<SessionNetworkInfo>,
    server_cipher: Option<Aes256GcmCipher>,
    address: SocketAddr,
}
pub struct SessionNetworkInfo {
    pub group: String,
    pub virtual_ip: u32,
    pub broadcast: Ipv4Addr,
    pub timestamp: i64,
}

impl VntSession {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            network_info: None,
            server_cipher: None,
            address,
        }
    }

    pub fn address(&self) -> &SocketAddr {
        &self.address
    }

    pub fn network_info(&self) -> Option<&SessionNetworkInfo> {
        self.network_info.as_ref()
    }
    pub fn enter_network(&mut self, network_info: SessionNetworkInfo) {
        self.network_info.replace(network_info);
    }
    pub fn server_cipher(&self) -> Option<&Aes256GcmCipher> {
        self.server_cipher.as_ref()
    }
    pub async fn enter_cipher(&mut self, controller: &Controller, server_cipher: Aes256GcmCipher) {
        self.server_cipher.replace(server_cipher.clone());
        controller
            .insert_cipher_session(self.address, server_cipher)
            .await;
    }
    pub async fn leave(self, controller: &Controller) {
        if self.server_cipher.is_some() {
            controller.remove_cipher_session(&self.address);
        }
        if let Some(network_context) = self.network_info {
            if controller
                .with_network_write(&network_context.group, |guard| {
                    if let Some(client_info) = guard.clients.get_mut(&network_context.virtual_ip) {
                        if client_info.address != self.address
                            && client_info.timestamp != network_context.timestamp
                        {
                            return;
                        }
                        client_info.online = false;
                        controller.set_tcp_sender(
                            &network_context.group,
                            network_context.virtual_ip,
                            None,
                        );
                        guard.epoch += 1;
                    }
                })
                .is_some()
            {
                controller
                    .insert_ip_session(
                        (network_context.group, network_context.virtual_ip),
                        self.address,
                    )
                    .await;
            }
        }
    }
}

pub struct Controller {
    // group -> NetworkInfo
    virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>>,
    // (group,ip) -> addr  用于客户端过期，只有客户端离线才设置
    ip_session: ExpireMap<(String, u32), SocketAddr>,
    // 加密密钥
    cipher_session: Arc<DashMap<SocketAddr, Arc<Aes256GcmCipher>>>,
    // web登录状态
    auth_map: ExpireMap<String, ()>,
    // wg公钥 -> wg配置
    wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>>,
    // (group, virtual_ip) -> runtime sender info
    client_runtime: Arc<DashMap<(String, u32), ClientRuntime>>,
}

#[derive(Clone, Default)]
pub struct ClientRuntime {
    pub tcp_sender: Option<Sender<Vec<u8>>>,
    pub wg_sender: Option<Sender<(Vec<u8>, Ipv4Addr)>>,
}

impl Controller {
    pub fn new() -> Self {
        let wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>> = Default::default();
        // 网段7天未使用则回收
        let virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>> =
            ExpireMap::new(|_k, v: &Arc<RwLock<NetworkInfo>>| {
                let lock = v.read();
                if !lock.clients.is_empty() {
                    // 存在客户端的不过期
                    return Some(Duration::from_secs(7 * 24 * 3600));
                }
                None
            });
        let virtual_network_ = virtual_network.clone();
        // ip一天未使用则回收
        let ip_session: ExpireMap<(String, u32), SocketAddr> = ExpireMap::new(move |key, addr| {
            let (group_id, ip) = &key;
            log::info!(
                "ip_session eviction group_id={},ip={},addr={}",
                group_id,
                Ipv4Addr::from(*ip),
                addr
            );
            if let Some(v) = virtual_network_.get(group_id) {
                let mut lock = v.write();
                if let Some(dev) = lock.clients.get(ip) {
                    if !dev.online && &dev.address == addr {
                        lock.clients.remove(ip);
                        lock.epoch += 1;
                    }
                }
            }
            None
        });

        let auth_map = ExpireMap::new(|_k, _v| None);
        Self {
            virtual_network,
            ip_session,
            cipher_session: Default::default(),
            auth_map,
            wg_group_map,
            client_runtime: Default::default(),
        }
    }
}

impl Controller {
    pub fn with_network_read<T, F>(&self, group: &str, f: F) -> Option<T>
    where
        F: FnOnce(&NetworkInfo) -> T,
    {
        self.virtual_network.get(&group.to_string()).map(|network_info| {
            let guard = network_info.read();
            f(&guard)
        })
    }
    pub fn with_network_write<T, F>(&self, group: &str, f: F) -> Option<T>
    where
        F: FnOnce(&mut NetworkInfo) -> T,
    {
        self.virtual_network.get(&group.to_string()).map(|network_info| {
            let mut guard = network_info.write();
            f(&mut guard)
        })
    }
    pub fn remove_network<T, F>(&self, group: &str, f: F) -> Option<T>
    where
        F: FnOnce(&mut NetworkInfo) -> T,
    {
        let removed = self.virtual_network.remove(&group.to_string());
        if let Some(network_info) = removed {
            self.client_runtime
                .retain(|(group_id, _), _| group_id.as_str() != group);
            let mut guard = network_info.write();
            Some(f(&mut guard))
        } else {
            None
        }
    }
    pub fn group_ids(&self) -> Vec<String> {
        self.virtual_network
            .key_values()
            .into_iter()
            .map(|(group, _)| group)
            .collect()
    }
    pub fn all_client_info(&self) -> Vec<(String, Vec<SimpleClientInfo>)> {
        self.virtual_network
            .key_values()
            .into_iter()
            .map(|(group, network_info)| {
                let clients = network_info.read().clients.values().map(SimpleClientInfo::from).collect();
                (group, clients)
            })
            .collect()
    }
    pub async fn with_or_create_network_write<T, C, F>(
        &self,
        group: String,
        create: C,
        f: F,
    ) -> T
    where
        C: FnOnce() -> (Duration, NetworkInfo),
        F: FnOnce(&mut NetworkInfo) -> T,
    {
        let network_info = self
            .virtual_network
            .optionally_get_with(group, || {
                let (duration, network_info) = create();
                (duration, Arc::new(parking_lot::RwLock::new(network_info)))
            })
            .await;
        let mut guard = network_info.write();
        f(&mut guard)
    }
    pub async fn insert_auth(&self, auth: String, expire: Duration) {
        self.auth_map.insert(auth, (), expire).await;
    }
    pub fn contains_auth(&self, auth: &str) -> bool {
        self.auth_map.get(&auth.to_string()).is_some()
    }
    pub fn insert_wg_group(&self, public_key: [u8; 32], wireguard_config: WireGuardConfig) {
        self.wg_group_map.insert(public_key, wireguard_config);
    }
    pub fn get_wg_group(&self, public_key: &[u8; 32]) -> Option<WireGuardConfig> {
        self.wg_group_map.get(public_key).map(|v| v.clone())
    }
    pub fn remove_wg_group(&self, public_key: &[u8; 32]) -> Option<WireGuardConfig> {
        self.wg_group_map.remove(public_key).map(|(_, v)| v)
    }
    pub async fn insert_cipher_session(&self, key: SocketAddr, value: Aes256GcmCipher) {
        self.cipher_session.insert(key, Arc::new(value));
    }
    pub fn get_cipher_session(&self, key: &SocketAddr) -> Option<Arc<Aes256GcmCipher>> {
        self.cipher_session.get(key).map(|v| v.clone())
    }
    pub fn remove_cipher_session(&self, key: &SocketAddr) -> Option<Arc<Aes256GcmCipher>> {
        self.cipher_session.remove(key).map(|(_, v)| v)
    }
    pub async fn insert_ip_session(&self, key: (String, u32), value: SocketAddr) {
        self.ip_session
            .insert(key, value, Duration::from_secs(24 * 3600))
            .await
    }
    pub fn set_tcp_sender(
        &self,
        group: &str,
        virtual_ip: u32,
        tcp_sender: Option<Sender<Vec<u8>>>,
    ) {
        self.set_client_runtime(group, virtual_ip, |runtime| runtime.tcp_sender = tcp_sender);
    }
    pub fn get_tcp_sender(&self, group: &str, virtual_ip: u32) -> Option<Sender<Vec<u8>>> {
        self.client_runtime
            .get(&(group.to_string(), virtual_ip))
            .and_then(|runtime| runtime.tcp_sender.clone())
    }
    pub fn set_wg_sender(
        &self,
        group: &str,
        virtual_ip: u32,
        wg_sender: Option<Sender<(Vec<u8>, Ipv4Addr)>>,
    ) {
        self.set_client_runtime(group, virtual_ip, |runtime| runtime.wg_sender = wg_sender);
    }
    pub fn get_wg_sender(
        &self,
        group: &str,
        virtual_ip: u32,
    ) -> Option<Sender<(Vec<u8>, Ipv4Addr)>> {
        self.client_runtime
            .get(&(group.to_string(), virtual_ip))
            .and_then(|runtime| runtime.wg_sender.clone())
    }

    fn set_client_runtime<F>(&self, group: &str, virtual_ip: u32, f: F)
    where
        F: FnOnce(&mut ClientRuntime),
    {
        let key = (group.to_string(), virtual_ip);
        let mut runtime = self
            .client_runtime
            .get(&key)
            .map(|v| v.value().clone())
            .unwrap_or_default();
        f(&mut runtime);
        if runtime.tcp_sender.is_none() && runtime.wg_sender.is_none() {
            self.client_runtime.remove(&key);
        } else {
            self.client_runtime.insert(key, runtime);
        }
    }
}
