//! Prebound logical sockets provide the entire UDP transport, including across ICE restarts.

use anyhow::Result;
use rtc::ice::mdns::MulticastDnsMode;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
};
use webrtc::runtime::{AsyncUdpSocket, Receiver, RecvMeta, Sender, Transmit, channel};

mod common;
use common::{block_on, runtime, timeout};

struct Handler {
    gathered: Sender<()>,
    remote_channel: Sender<Arc<dyn DataChannel>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gathered.try_send(());
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let _ = self.remote_channel.try_send(channel);
    }
}

fn builder() -> PeerConnectionBuilder<SocketAddr> {
    let (gathered, _) = channel(1);
    let (remote_channel, _) = channel(1);
    PeerConnectionBuilder::new()
        .with_runtime(runtime())
        .with_handler(Arc::new(Handler {
            gathered,
            remote_channel,
        }))
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_multicast_dns_mode(MulticastDnsMode::Disabled)
                .with_discard_local_candidates_during_ice_restart(true)
                .build(),
        )
}

fn socket() -> Result<Arc<dyn AsyncUdpSocket>> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    Ok(runtime().wrap_udp_socket(socket)?)
}

async fn negotiate(
    a: &impl PeerConnection,
    a_gathered: &mut Receiver<()>,
    b: &impl PeerConnection,
    b_gathered: &mut Receiver<()>,
) -> Result<()> {
    let offer = a.create_offer(None).await?;
    a.set_local_description(offer).await?;
    a_gathered.recv().await.expect("offerer gathered");
    b.set_remote_description(a.local_description().await.expect("offer"))
        .await?;
    let answer = b.create_answer(None).await?;
    b.set_local_description(answer).await?;
    b_gathered.recv().await.expect("answerer gathered");
    a.set_remote_description(b.local_description().await.expect("answer"))
        .await?;
    Ok(())
}

async fn assert_local_binding(pc: &impl PeerConnection, addr: SocketAddr) -> Result<()> {
    let candidates = pc
        .sctp()
        .await
        .expect("SCTP negotiated")
        .transport()
        .ice_transport()
        .get_local_candidates()
        .await?;
    assert!(!candidates.is_empty());
    for candidate in candidates {
        assert_eq!(candidate.address, addr.ip().to_string());
        assert_eq!(candidate.port, addr.port());
    }
    Ok(())
}

async fn receive_message(dc: &Arc<dyn DataChannel>, expected: &[u8]) {
    loop {
        match dc.poll().await.expect("data channel still open") {
            DataChannelEvent::OnMessage(message) => {
                assert_eq!(&message.data[..], expected);
                break;
            }
            DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                panic!("data channel closed before receiving the message");
            }
            _ => {}
        }
    }
}

#[test]
fn supplied_sockets_exchange_data_and_survive_restart_and_close() {
    block_on(async {
        timeout(Duration::from_secs(30), async {
            let a_socket = socket()?;
            let b_socket = socket()?;
            let a_addr = a_socket.local_addr()?;
            let b_addr = b_socket.local_addr()?;
            let (a_gathered, mut a_gather_rx) = channel(1);
            let (b_gathered, mut b_gather_rx) = channel(1);
            let (a_remote, _a_remote_rx) = channel(1);
            let (b_remote, mut b_remote_rx) = channel(1);
            let a = builder()
                .with_udp_sockets(vec![Arc::clone(&a_socket)])
                .with_handler(Arc::new(Handler {
                    gathered: a_gathered,
                    remote_channel: a_remote,
                }))
                .build()
                .await?;
            let b = builder()
                .with_udp_sockets(vec![Arc::clone(&b_socket)])
                .with_handler(Arc::new(Handler {
                    gathered: b_gathered,
                    remote_channel: b_remote,
                }))
                .build()
                .await?;

            let a_dc = a.create_data_channel("injected", None).await?;
            negotiate(&a, &mut a_gather_rx, &b, &mut b_gather_rx).await?;
            loop {
                if matches!(a_dc.poll().await, Some(DataChannelEvent::OnOpen)) {
                    break;
                }
            }
            let b_dc = b_remote_rx.recv().await.expect("remote channel");
            a_dc.send_text("before restart").await?;
            receive_message(&b_dc, b"before restart").await;
            b_dc.send_text("reply").await?;
            receive_message(&a_dc, b"reply").await;
            assert_local_binding(&a, a_addr).await?;
            assert_local_binding(&b, b_addr).await?;

            a.restart_ice().await?;
            negotiate(&a, &mut a_gather_rx, &b, &mut b_gather_rx).await?;
            assert_local_binding(&a, a_addr).await?;
            assert_local_binding(&b, b_addr).await?;
            a_dc.send_text("after restart").await?;
            receive_message(&b_dc, b"after restart").await;
            b_dc.send_text("restart reply").await?;
            receive_message(&a_dc, b"restart reply").await;

            a.close().await?;
            b.close().await?;
            drop(a);
            drop(b);
            a_socket
                .send_to(b"caller still owns socket", b_addr)
                .await?;
            let mut buf = [0; 128];
            loop {
                let (len, from) = b_socket.recv_from(&mut buf).await?;
                if &buf[..len] == b"caller still owns socket" {
                    assert_eq!(from, a_addr);
                    break;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .expect("supplied-socket data/restart test timed out")
        .unwrap();
    });
}

#[derive(Debug)]
struct InvalidLocalAddr;

impl AsyncUdpSocket for InvalidLocalAddr {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::other("injected local_addr failure"))
    }

    fn poll_send(&self, _: &mut Context<'_>, _: &Transmit<'_>) -> Poll<io::Result<usize>> {
        panic!("invalid socket must not be used")
    }

    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        _: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        panic!("invalid socket must not be used")
    }
}

#[test]
fn supplied_and_bound_sockets_gather_together() {
    block_on(async {
        timeout(Duration::from_secs(10), async {
            let supplied = socket().unwrap();
            let supplied_addr = supplied.local_addr().unwrap();
            let (gathered, mut gather_rx) = channel(1);
            let (remote_channel, _) = channel(1);
            let pc = builder()
                .with_handler(Arc::new(Handler {
                    gathered,
                    remote_channel,
                }))
                .with_udp_sockets(vec![supplied])
                .with_udp_addrs(vec!["127.0.0.1:0".parse().unwrap()])
                .build()
                .await
                .unwrap();
            let _dc = pc.create_data_channel("mixed", None).await.unwrap();
            let offer = pc.create_offer(None).await.unwrap();
            pc.set_local_description(offer).await.unwrap();
            gather_rx.recv().await.expect("gathered");
            let description = pc.local_description().await.expect("local offer");
            let ports: std::collections::BTreeSet<u16> = description
                .sdp
                .lines()
                .filter_map(|line| line.strip_prefix("a=candidate:"))
                .filter_map(|candidate| candidate.split_whitespace().nth(5))
                .map(|port| port.parse().expect("candidate port"))
                .collect();
            assert_eq!(ports.len(), 2, "both supplied and bound sockets gathered");
            assert!(ports.contains(&supplied_addr.port()));
            pc.close().await.unwrap();
        })
        .await
        .expect("mixed supplied/bound gathering timed out");
    });
}

#[test]
fn supplied_socket_errors_are_explicit() {
    block_on(async {
        timeout(Duration::from_secs(10), async {
            let supplied = socket().unwrap();
            let addr = supplied.local_addr().unwrap();
            let cases = [
                (
                    builder().with_udp_sockets(vec![Arc::new(InvalidLocalAddr)]),
                    "injected local_addr failure",
                ),
                (
                    builder().with_udp_sockets(vec![supplied.clone(), supplied.clone()]),
                    "duplicate UDP local address",
                ),
                (
                    builder()
                        .with_udp_sockets(vec![supplied])
                        .with_udp_addrs(vec![addr]),
                    "duplicate UDP local address",
                ),
            ];
            for (builder, expected) in cases {
                let Err(error) = builder.build().await else {
                    panic!("build must reject {expected}");
                };
                assert!(
                    error.to_string().contains(expected),
                    "expected {expected}, got {error}"
                );
            }
        })
        .await
        .expect("invalid-socket builds timed out");
    });
}
