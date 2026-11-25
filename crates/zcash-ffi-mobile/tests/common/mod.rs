//! A plaintext h2 mock of the `CompactTxStreamer` service, enough for the read
//! path: `GetLatestBlock`, `GetBlock`, `GetBlockRange` and `GetTransaction`.
//!
//! The service is hand-routed by RPC path, as the mock in `zcash-sync` is, because
//! `zcash_client_backend` generates only the client. An RPC the engine starts
//! calling that is not routed here answers `unimplemented`, which fails the test
//! with the RPC's name.
//!
//! The server runs on its own thread and runtime, apart from the binding's.

#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::codegen::http;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, RawTransaction, TxFilter,
};

const SERVICE: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

/// Timestamp of a block: linear in the height, so interpolation search converges.
pub fn block_time(height: u64) -> u32 {
    1_600_000_000 + (height as u32) * 75
}

#[derive(Clone)]
pub struct MockConfig {
    pub tip: u64,
    /// Pause before each block of a `GetBlockRange` stream.
    pub block_delay: Duration,
    /// Fail `GetLatestBlock` with `unavailable`.
    pub fail_chain_tip: bool,
    /// End a `GetBlockRange` stream with `unavailable` after this many blocks.
    pub range_error_after: Option<u64>,
    /// Raw transactions served by `GetTransaction`, keyed by display-order txid.
    pub transactions: HashMap<String, Vec<u8>>,
}

impl Default for MockConfig {
    fn default() -> Self {
        MockConfig {
            tip: 1_689_000,
            block_delay: Duration::ZERO,
            fail_chain_tip: false,
            range_error_after: None,
            transactions: HashMap::new(),
        }
    }
}

pub struct MockServer {
    pub url: String,
    open_connections: Arc<AtomicUsize>,
    total_connections: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MockServer {
    pub fn start(config: MockConfig) -> MockServer {
        let open = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let (open_t, total_t) = (open.clone(), total.clone());
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let incoming = futures::stream::unfold(listener, move |l| {
                    let (open, total) = (open_t.clone(), total_t.clone());
                    async move {
                        let item = l.accept().await.map(|(socket, _)| {
                            open.fetch_add(1, Ordering::SeqCst);
                            total.fetch_add(1, Ordering::SeqCst);
                            Counted { socket, open }
                        });
                        Some((item, l))
                    }
                });
                let _ = tonic::transport::Server::builder()
                    .serve_with_incoming_shutdown(
                        MockStreamer {
                            config: Arc::new(config),
                        },
                        incoming,
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await;
            });
        });

        let addr = addr_rx.recv().unwrap();
        MockServer {
            url: format!("http://{addr}"),
            open_connections: open,
            total_connections: total,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    /// TCP connections currently open to the mock.
    pub fn open_connections(&self) -> usize {
        self.open_connections.load(Ordering::SeqCst)
    }

    /// TCP connections the mock has accepted since it started.
    pub fn total_connections(&self) -> usize {
        self.total_connections.load(Ordering::SeqCst)
    }

    /// Poll until no connection is open, or `within` elapses.
    pub fn wait_until_idle(&self, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        while std::time::Instant::now() < deadline {
            if self.open_connections() == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.open_connections() == 0
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A socket that counts itself out when the connection closes.
struct Counted {
    socket: tokio::net::TcpStream,
    open: Arc<AtomicUsize>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for Counted {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

#[derive(Clone)]
struct MockStreamer {
    config: Arc<MockConfig>,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One unary RPC answered by a closure.
struct Unary<Req, Resp>(Arc<dyn Fn(Req) -> Result<Resp, tonic::Status> + Send + Sync>);

impl<Req, Resp> tonic::server::UnaryService<Req> for Unary<Req, Resp>
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    type Response = Resp;
    type Future = std::future::Ready<Result<tonic::Response<Resp>, tonic::Status>>;
    fn call(&mut self, request: tonic::Request<Req>) -> Self::Future {
        std::future::ready((self.0)(request.into_inner()).map(tonic::Response::new))
    }
}

struct BlockRangeSvc(Arc<MockConfig>);

impl tonic::server::ServerStreamingService<BlockRange> for BlockRangeSvc {
    type Response = CompactBlock;
    type ResponseStream = Pin<Box<dyn Stream<Item = Result<CompactBlock, tonic::Status>> + Send>>;
    type Future = std::future::Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<BlockRange>) -> Self::Future {
        let range = request.into_inner();
        let start = range.start.map(|b| b.height).unwrap_or(0);
        let end = range.end.map(|b| b.height).unwrap_or(0);
        let config = self.0.clone();
        let stream = futures::stream::unfold(start, move |height| {
            let config = config.clone();
            async move {
                if height > end {
                    return None;
                }
                if let Some(limit) = config.range_error_after {
                    if height - start >= limit {
                        let err = tonic::Status::unavailable("mock range failure");
                        return Some((Err(err), end + 1));
                    }
                }
                if !config.block_delay.is_zero() {
                    tokio::time::sleep(config.block_delay).await;
                }
                Some((Ok(block(height)), height + 1))
            }
        });
        std::future::ready(Ok(tonic::Response::new(
            Box::pin(stream) as Self::ResponseStream
        )))
    }
}

/// A block with no transactions and no chain metadata.
fn block(height: u64) -> CompactBlock {
    let mut hash = vec![0u8; 32];
    hash[..8].copy_from_slice(&height.to_le_bytes());
    CompactBlock {
        height,
        hash,
        time: block_time(height),
        ..Default::default()
    }
}

impl tonic::codegen::Service<http::Request<tonic::body::Body>> for MockStreamer {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();
            let Some(method) = path.strip_prefix(SERVICE) else {
                return Ok(tonic::Status::unimplemented(path).into_http());
            };
            match method {
                "GetLatestBlock" => {
                    let cfg = config.clone();
                    let svc = Unary(Arc::new(move |_: ChainSpec| {
                        if cfg.fail_chain_tip {
                            return Err(tonic::Status::unavailable("mock tip failure"));
                        }
                        Ok(BlockId {
                            height: cfg.tip,
                            hash: vec![],
                        })
                    }));
                    let codec = tonic_prost::ProstCodec::<BlockId, ChainSpec>::default();
                    Ok(tonic::server::Grpc::new(codec).unary(svc, req).await)
                }
                "GetBlock" => {
                    let svc = Unary(Arc::new(|id: BlockId| Ok(block(id.height))));
                    let codec = tonic_prost::ProstCodec::<CompactBlock, BlockId>::default();
                    Ok(tonic::server::Grpc::new(codec).unary(svc, req).await)
                }
                "GetBlockRange" => {
                    let codec = tonic_prost::ProstCodec::<CompactBlock, BlockRange>::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .server_streaming(BlockRangeSvc(config), req)
                        .await)
                }
                "GetTransaction" => {
                    let svc = Unary(Arc::new(move |f: TxFilter| {
                        let mut id = f.hash;
                        id.reverse();
                        match config.transactions.get(&hex::encode(id)) {
                            Some(data) => Ok(RawTransaction {
                                data: data.clone(),
                                height: 0,
                            }),
                            None => Err(tonic::Status::not_found("no such transaction")),
                        }
                    }));
                    let codec = tonic_prost::ProstCodec::<RawTransaction, TxFilter>::default();
                    Ok(tonic::server::Grpc::new(codec).unary(svc, req).await)
                }
                other => Ok(tonic::Status::unimplemented(other.to_string()).into_http()),
            }
        })
    }
}
