use chrono::Local;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use crate::cipher::Aes256GcmCipher;
use crate::core::control::expire_map::ExpireMap;
use crate::core::entity::{ClientInfo, NetworkInfo, SimpleClientInfo, WireGuardConfig};
use crate::error::Error;

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

pub struct RegisterClientRequest {
    pub group_id: String,
    // ip 0表示自动分配
    pub virtual_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    // 允许分配不一样的ip
    pub allow_ip_change: bool,
    // 设备ID
    pub device_id: String,
    // 版本
    pub version: String,
    // 名称
    pub name: String,
    // 客户端间是否加密
    pub client_secret: bool,
    // 加密hash
    pub client_secret_hash: Vec<u8>,
    // 和服务端是否加密
    pub server_secret: bool,
    // 链接服务器的来源地址
    pub address: SocketAddr,
    pub tcp_sender: Option<Sender<Vec<u8>>>,
    // 是否在线
    pub online: bool,
    // wireguard客户端公钥
    pub wireguard: Option<[u8; 32]>,
}

pub struct RegisterClientResponse {
    pub timestamp: i64,
    pub virtual_ip: Ipv4Addr,
    // 纪元号
    pub epoch: u64,
    pub client_list: Vec<SimpleClientInfo>,
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
        self.virtual_network
            .get(&group.to_string())
            .map(|network_info| {
                let guard = network_info.read();
                f(&guard)
            })
    }
    pub fn with_network_write<T, F>(&self, group: &str, f: F) -> Option<T>
    where
        F: FnOnce(&mut NetworkInfo) -> T,
    {
        self.virtual_network
            .get(&group.to_string())
            .map(|network_info| {
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
                let clients = network_info
                    .read()
                    .clients
                    .values()
                    .map(SimpleClientInfo::from)
                    .collect();
                (group, clients)
            })
            .collect()
    }
    pub async fn with_or_create_network_write<T, C, F>(&self, group: String, create: C, f: F) -> T
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

    pub async fn generate_ip(
        &self,
        register_request: RegisterClientRequest,
    ) -> anyhow::Result<RegisterClientResponse> {
        let gateway: u32 = register_request.gateway.into();
        let netmask: u32 = register_request.netmask.into();
        let network: u32 = gateway & netmask;
        let mut virtual_ip: u32 = register_request.virtual_ip.into();
        let device_id = register_request.device_id;
        let allow_ip_change = register_request.allow_ip_change;
        let runtime_group_id = register_request.group_id.clone();
        let group_id = register_request.group_id;
        let tcp_sender = register_request.tcp_sender.clone();

        self.with_or_create_network_write(
            group_id,
            || {
                (
                    Duration::from_secs(7 * 24 * 3600),
                    NetworkInfo::new(network, netmask, gateway),
                )
            },
            |network_info| {
                // 可分配的ip段
                let ip_range = network + 1..gateway | (!netmask);
                let timestamp = Local::now().timestamp();
                let old_ip = Self::resolve_old_ip_and_requested_ip(
                    network_info,
                    gateway,
                    &ip_range,
                    &mut virtual_ip,
                    &device_id,
                    allow_ip_change,
                )?;

                Self::allocate_virtual_ip_if_needed(network_info, &ip_range, &mut virtual_ip)?;

                let client_info = if old_ip == 0 {
                    network_info
                        .clients
                        .entry(virtual_ip)
                        .or_insert_with(ClientInfo::default)
                } else {
                    let client_info = network_info.clients.remove(&old_ip).unwrap();
                    network_info
                        .clients
                        .entry(virtual_ip)
                        .or_insert_with(|| client_info)
                };
                client_info.name = register_request.name;
                client_info.device_id = device_id;
                client_info.version = register_request.version;
                client_info.client_secret = register_request.client_secret;
                client_info.client_secret_hash = register_request.client_secret_hash;
                client_info.server_secret = register_request.server_secret;
                client_info.address = register_request.address;
                client_info.online = register_request.online;
                client_info.wireguard = register_request.wireguard;
                client_info.virtual_ip = virtual_ip;
                client_info.last_join_time = Local::now();
                client_info.timestamp = timestamp;

                network_info.epoch += 1;

                if old_ip != 0 && old_ip != virtual_ip {
                    self.set_tcp_sender(&runtime_group_id, old_ip, None);
                    self.set_wg_sender(&runtime_group_id, old_ip, None);
                }
                self.set_tcp_sender(&runtime_group_id, virtual_ip, tcp_sender);
                self.set_wg_sender(&runtime_group_id, virtual_ip, None);
                Ok(RegisterClientResponse {
                    timestamp,
                    virtual_ip: virtual_ip.into(),
                    epoch: network_info.epoch,
                    client_list: clients_info(&network_info.clients, virtual_ip),
                })
            },
        )
        .await
    }

    fn resolve_old_ip_and_requested_ip(
        lock: &mut NetworkInfo,
        gateway: u32,
        ip_range: &Range<u32>,
        virtual_ip: &mut u32,
        device_id: &str,
        allow_ip_change: bool,
    ) -> anyhow::Result<u32> {
        let insert = Self::handle_requested_ip(
            lock,
            gateway,
            ip_range,
            virtual_ip,
            device_id,
            allow_ip_change,
        )?;
        if !insert {
            return Ok(0);
        }
        Ok(Self::reuse_previous_device_ip(lock, virtual_ip, device_id))
    }

    fn handle_requested_ip(
        lock: &mut NetworkInfo,
        gateway: u32,
        ip_range: &Range<u32>,
        virtual_ip: &mut u32,
        device_id: &str,
        allow_ip_change: bool,
    ) -> anyhow::Result<bool> {
        if *virtual_ip == 0 {
            return Ok(true);
        }
        if gateway == *virtual_ip || !ip_range.contains(virtual_ip) {
            Err(Error::InvalidIp)?
        }
        //指定了ip
        if let Some(info) = lock.clients.get_mut(virtual_ip) {
            if info.device_id != device_id {
                //ip被占用了,并且不能更改ip
                if !allow_ip_change {
                    Err(Error::IpAlreadyExists)?
                }
                // 重新挑选ip
                *virtual_ip = 0;
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn reuse_previous_device_ip(lock: &NetworkInfo, virtual_ip: &mut u32, device_id: &str) -> u32 {
        // 找到上一次用的ip
        for (ip, x) in &lock.clients {
            if x.device_id == device_id {
                if *virtual_ip == 0 {
                    *virtual_ip = *ip;
                    return 0;
                }
                return *ip;
            }
        }
        0
    }

    fn allocate_virtual_ip_if_needed(
        lock: &NetworkInfo,
        ip_range: &Range<u32>,
        virtual_ip: &mut u32,
    ) -> anyhow::Result<()> {
        if *virtual_ip == 0 {
            // 从小到大找一个未使用的ip
            for ip in ip_range.clone() {
                if ip == lock.gateway_ip {
                    continue;
                }
                if !lock.clients.contains_key(&ip) {
                    *virtual_ip = ip;
                    break;
                }
            }
        }
        if *virtual_ip == 0 {
            log::error!("地址使用完:{:?}", lock);
            Err(Error::AddressExhausted)?
        }
        Ok(())
    }
}

fn clients_info(clients: &HashMap<u32, ClientInfo>, current_ip: u32) -> Vec<SimpleClientInfo> {
    clients
        .iter()
        .filter(|&(_, dev)| dev.virtual_ip != current_ip)
        .map(|(_, device_info)| device_info.into())
        .collect()
}
