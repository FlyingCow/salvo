//! rustls module
use std::error::Error as StdError;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::marker::PhantomData;
use std::sync::Arc;

use rustls::server::ClientHello;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls;
use tokio_rustls::server::TlsStream;

use crate::conn::{Accepted, Acceptor, HandshakeStream, Holding, Listener};
use crate::fuse::ArcFuseFactory;
use crate::http::uri::Scheme;
use crate::http::{HttpConnection, Version};

use super::config::ResolvesServerConfig;
use super::ServerConfig;

/// A wrapper of `Listener` with rustls.
pub struct RustlsListener<S, T, E> {
    config: S,
    inner: T,
    _phantom: PhantomData<E>,
}

impl<S, T, E> RustlsListener<S, T, E>
where
    S: ResolvesServerConfig<E> + Send + 'static,
    T: Listener + Send,
    E: StdError + Send,
{
    /// Create a new `RustlsListener`.
    #[inline]
    pub fn new(config: S, inner: T) -> Self {
        RustlsListener {
            config,
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, E> Listener for RustlsListener<S, T, E>
where
    S: ResolvesServerConfig<E> + Send + 'static,
    T: Listener + Send,
    T::Acceptor: Send + 'static,
    E: StdError + Send,
{
    type Acceptor = RustlsAcceptor<S, T::Acceptor, E>;

    async fn try_bind(self) -> crate::Result<Self::Acceptor> {
        Ok(RustlsAcceptor::new(self.config, self.inner.try_bind().await?))
    }
}

/// A wrapper of `Acceptor` with rustls.
pub struct RustlsAcceptor<S, T, E> {
    config: S,
    inner: T,
    holdings: Vec<Holding>,
    _phantom: PhantomData<E>,
}
impl<S, T, E> RustlsAcceptor<S, T, E>
where
    S: ResolvesServerConfig<E> + Send + 'static,
    T: Acceptor + Send,
    E: StdError + Send,
{
    /// Create a new `RustlsAcceptor`.
    pub fn new(config: S, inner: T) -> RustlsAcceptor<S, T, E> {
        let holdings = inner
            .holdings()
            .iter()
            .map(|h| {
                let mut versions = h.http_versions.clone();
                #[cfg(feature = "http1")]
                if !versions.contains(&Version::HTTP_11) {
                    versions.push(Version::HTTP_11);
                }
                #[cfg(feature = "http2")]
                if !versions.contains(&Version::HTTP_2) {
                    versions.push(Version::HTTP_2);
                }
                Holding {
                    local_addr: h.local_addr.clone(),
                    http_versions: versions,
                    http_scheme: Scheme::HTTPS,
                }
            })
            .collect();
        RustlsAcceptor {
            config,
            inner,
            holdings,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, E> Acceptor for RustlsAcceptor<S, T, E>
where
    S: ResolvesServerConfig<E> + Send + 'static,
    T: Acceptor + Send + 'static,
    <T as Acceptor>::Conn: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    E: StdError + Send,
{
    type Conn = HandshakeStream<TlsStream<T::Conn>>;

    fn holdings(&self) -> &[Holding] {
        &self.holdings
    }

    async fn accept(&mut self, fuse_factory: Option<ArcFuseFactory>) -> IoResult<Accepted<Self::Conn>> {
        let Accepted {
            conn,
            local_addr,
            remote_addr,
            ..
        } = self.inner.accept(fuse_factory).await?;

        let fusewire = conn.fusewire();

        let lazy_acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), conn);

        futures_util::pin_mut!(lazy_acceptor);

        match lazy_acceptor.as_mut().await {
            Ok(start) => {
                let client_hello: ClientHello = start.client_hello();
                let config_result = self.config.resolve(client_hello).await;

                match config_result {
                    Ok(config) => {

                        let config:Result<ServerConfig, _> = config.as_ref().clone().try_into();

                        if let Err(_err) = config {
                            return Err(IoError::new(ErrorKind::Other, "rustls: invalid tls config."))
                        }

                        let res: IoResult<Accepted<Self::Conn>> = Ok(Accepted {
                            conn: HandshakeStream::new(start.into_stream(Arc::new(config?)), fusewire),
                            local_addr,
                            remote_addr,
                            http_scheme: Scheme::HTTPS,
                        });

                        return res;
                    }
                    Err(_err) => return Err(IoError::new(ErrorKind::Other, "rustls: invalid tls config.")),
                }
            }
            Err(_err) => return Err(IoError::new(ErrorKind::Other, "rustls: invalid tls config.")),
        }
    }
}
