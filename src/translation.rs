//! Explicit non-transparent cross-family transport. The normal data path never enters this module.
use crate::model::*;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch, RwLock, Semaphore},
    task::JoinHandle,
};

struct Runtime {
    fingerprint: String,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}
pub struct TranslationManager {
    runtimes: HashMap<(u64, u16), Runtime>,
    bans: Arc<RwLock<Vec<Ban>>>,
    permits: Arc<Semaphore>,
}
impl Default for TranslationManager {
    fn default() -> Self {
        Self::new()
    }
}
impl TranslationManager {
    pub fn new() -> Self {
        Self {
            runtimes: HashMap::new(),
            bans: Arc::new(RwLock::new(vec![])),
            permits: Arc::new(Semaphore::new(1024)),
        }
    }
    pub async fn reconcile(&mut self, snapshot: &StateSnapshot) -> Result<()> {
        *self.bans.write().await = snapshot.bans.clone();
        let mut desired = HashMap::new();
        for f in snapshot
            .forwards
            .iter()
            .filter(|f| f.enabled && f.mode == ForwardMode::Translate)
        {
            let Some(a) = snapshot.agents.iter().find(|a| {
                a.id == f.agent_id
                    && a.status == AgentStatus::Active
                    && a.applied_generation >= f.generation
            }) else {
                continue;
            };
            for offset in 0..f.listen_ports.len() {
                let port = f.listen_ports.start + offset as u16;
                let listen = SocketAddr::new(f.listen_ip, port);
                let target = SocketAddr::new(f.target_ip(a), f.target_ports.start + offset as u16);
                desired.insert((f.id, port), (listen, target, f.protocol));
            }
        }
        self.runtimes.retain(|key, runtime| {
            desired
                .get(key)
                .is_some_and(|value| runtime.fingerprint == format!("{:?}", value))
        });
        for (key, (listen, target, protocol)) in desired {
            if self.runtimes.contains_key(&key) {
                continue;
            }
            let fingerprint = format!("{:?}", (listen, target, protocol));
            let (stop, rx) = watch::channel(false);
            let bans = self.bans.clone();
            let permits = self.permits.clone();
            let task = match protocol {
                Protocol::Tcp => {
                    let listener =
                        bind_tcp(listen).with_context(|| format!("translation bind {listen}"))?;
                    tokio::spawn(tcp_loop(listener, target, key.0, bans, permits, rx))
                }
                Protocol::Udp => {
                    let listener = Arc::new(
                        bind_udp(listen).with_context(|| format!("translation bind {listen}"))?,
                    );
                    tokio::spawn(udp_loop(listener, target, key.0, bans, permits, rx))
                }
            };
            tracing::warn!(forward_id=key.0,%listen,%target,"cross-family translation enabled; target does not see original client IP");
            self.runtimes.insert(
                key,
                Runtime {
                    fingerprint,
                    stop,
                    task,
                },
            );
        }
        Ok(())
    }
}
fn bind_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(socket.into())?)
}
fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
async fn banned(bans: &RwLock<Vec<Ban>>, id: u64, ip: IpAddr) -> bool {
    let time = now();
    bans.read()
        .await
        .iter()
        .any(|b| b.forward_id == id && b.ip == ip && b.expires_at > time)
}
async fn tcp_loop(
    listener: TcpListener,
    target: SocketAddr,
    id: u64,
    bans: Arc<RwLock<Vec<Ban>>>,
    permits: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let accepted =
            tokio::select! { biased; _=stop.changed()=>break, value=listener.accept()=>value };
        let Ok((mut client, addr)) = accepted else {
            break;
        };
        if banned(&bans, id, addr.ip()).await {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let bans = bans.clone();
        let mut stop = stop.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tracing::info!(forward_id=id,original_client=%addr,%target,"translation connection");
            let Ok(Ok(mut upstream)) =
                tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target)).await
            else {
                return;
            };
            let transfer = tokio::io::copy_bidirectional(&mut client, &mut upstream);
            tokio::pin!(transfer);
            let mut timer = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! { biased; _=stop.changed()=>break, _=&mut transfer=>break, _=timer.tick()=>if banned(&bans,id,addr.ip()).await {break} }
            }
        });
    }
}
async fn udp_loop(
    listener: Arc<UdpSocket>,
    target: SocketAddr,
    id: u64,
    bans: Arc<RwLock<Vec<Ban>>>,
    permits: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) {
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (expired_tx, mut expired_rx) = mpsc::channel::<SocketAddr>(1024);
    let mut buffer = vec![0; 65535];
    loop {
        let packet = tokio::select! { biased; _=stop.changed()=>break, Some(addr)=expired_rx.recv()=>{sessions.remove(&addr);continue}, value=listener.recv_from(&mut buffer)=>value };
        let Ok((len, addr)) = packet else { break };
        if banned(&bans, id, addr.ip()).await {
            continue;
        }
        if let Some(channel) = sessions.get(&addr) {
            if channel.try_send(buffer[..len].to_vec()).is_ok() {
                continue;
            }
            if !channel.is_closed() {
                continue;
            }
            sessions.remove(&addr);
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let Ok(upstream) = UdpSocket::bind(bind).await else {
            continue;
        };
        if upstream.connect(target).await.is_err() {
            continue;
        }
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
        let _ = tx.try_send(buffer[..len].to_vec());
        sessions.insert(addr, tx);
        let public = listener.clone();
        let bans = bans.clone();
        let expired = expired_tx.clone();
        let mut stop = stop.clone();
        tracing::info!(forward_id=id,original_client=%addr,%target,"translation UDP session");
        tokio::spawn(async move {
            let _permit = permit;
            let mut reply = vec![0; 65535];
            let mut last = tokio::time::Instant::now();
            let mut timer = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! { biased;
                    _=stop.changed()=>break,
                    packet=rx.recv()=>{let Some(packet)=packet else {break}; if banned(&bans,id,addr.ip()).await {break}
                if upstream.send(&packet).await.is_err(){break} last=tokio::time::Instant::now();},
                    response=upstream.recv(&mut reply)=>{let Ok(n)=response else {break}; if banned(&bans,id,addr.ip()).await {break}
                if public.send_to(&reply[..n],addr).await.is_err(){break} last=tokio::time::Instant::now();},
                    _=timer.tick()=>if last.elapsed()>Duration::from_secs(60) || banned(&bans,id,addr.ip()).await {break},
                }
            }
            let _ = expired.send(addr).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn expired_and_other_forward_bans_do_not_apply() {
        let ip = "192.0.2.1".parse().unwrap();
        let bans = RwLock::new(vec![
            Ban {
                id: 1,
                agent_id: "a".into(),
                forward_id: 7,
                ip,
                expires_at: now() - 1,
            },
            Ban {
                id: 2,
                agent_id: "b".into(),
                forward_id: 8,
                ip,
                expires_at: now() + 60,
            },
        ]);
        assert!(!banned(&bans, 7, ip).await);
        assert!(banned(&bans, 8, ip).await);
    }
    fn snapshot(listen: SocketAddr, target: SocketAddr, protocol: Protocol) -> StateSnapshot {
        StateSnapshot {
            generation: 1,
            agents: vec![AgentRecord {
                id: "a".into(),
                name: "a".into(),
                public_key: "test".into(),
                tunnel_ipv4: if target.is_ipv4() {
                    match target.ip() {
                        IpAddr::V4(ip) => ip,
                        _ => unreachable!(),
                    }
                } else {
                    std::net::Ipv4Addr::LOCALHOST
                },
                tunnel_ipv6: if target.is_ipv6() {
                    match target.ip() {
                        IpAddr::V6(ip) => ip,
                        _ => unreachable!(),
                    }
                } else {
                    std::net::Ipv6Addr::LOCALHOST
                },
                status: AgentStatus::Active,
                attempt_id: "a".into(),
                generation: 1,
                applied_generation: 1,
                last_error: None,
                created_at: now(),
                pending_deadline: None,
            }],
            forwards: vec![Forward {
                id: 1,
                agent_id: "a".into(),
                listen_ip: listen.ip(),
                listen_ports: PortRange {
                    start: listen.port(),
                    end: listen.port(),
                },
                target_ports: PortRange {
                    start: target.port(),
                    end: target.port(),
                },
                protocol,
                mode: ForwardMode::Translate,
                ingress: crate::model::Ingress::Public,
                target_family: Family::of(target.ip()),
                enabled: true,
                generation: 1,
            }],
            bans: vec![],
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn tcp_translation_v4_to_v6_carries_bytes_and_enforces_ban() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("[::1]:0").await.unwrap();
        let target = backend.local_addr().unwrap();
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let echo = tokio::spawn(async move {
            let (mut socket, addr) = backend.accept().await.unwrap();
            assert!(addr.is_ipv6());
            let mut data = [0; 4];
            socket.read_exact(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
        });
        let mut manager = TranslationManager::new();
        let mut state = snapshot(listen, target, Protocol::Tcp);
        manager.reconcile(&state).await.unwrap();
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"rift").await.unwrap();
        let mut reply = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"rift");
        echo.await.unwrap();
        state.bans.push(Ban {
            id: 1,
            agent_id: "a".into(),
            forward_id: 1,
            ip: listen.ip(),
            expires_at: now() + 60,
        });
        manager.reconcile(&state).await.unwrap();
        let mut blocked = TcpStream::connect(listen).await.unwrap();
        let mut data = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(3), blocked.read(&mut data))
            .await
            .unwrap();
        assert!(result.is_err() || result.unwrap() == 0);
    }
    #[tokio::test]
    async fn udp_translation_v6_to_v4_roundtrip() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = backend.local_addr().unwrap();
        let reserve = UdpSocket::bind("[::1]:0").await.unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let echo = tokio::spawn(async move {
            let mut data = [0; 32];
            let (n, addr) = backend.recv_from(&mut data).await.unwrap();
            assert!(addr.is_ipv4());
            backend.send_to(&data[..n], addr).await.unwrap();
        });
        let mut manager = TranslationManager::new();
        manager
            .reconcile(&snapshot(listen, target, Protocol::Udp))
            .await
            .unwrap();
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(listen).await.unwrap();
        client.send(b"rift-udp").await.unwrap();
        let mut data = [0; 32];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..n], b"rift-udp");
        echo.await.unwrap();
    }
}
