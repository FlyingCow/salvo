//! rustls module
use std::error::Error as StdError;
use std::fmt::{self, Debug, Formatter};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::server::ClientHello;
use tokio_rustls::server::TlsStream;

use crate::conn::tcp::{DynTcpAcceptor, TcpCoupler, ToDynTcpAcceptor};
use crate::conn::{Accepted, Acceptor, HandshakeStream, Holding, Listener};
use crate::fuse::ArcFuseFactory;
use crate::http::uri::Scheme;

use super::ServerConfig;
use super::config::ResolvesServerConfig;

/// A wrapper of `Listener` with rustls.
pub struct RustlsAsyncListener<R, T, E> {
    config_resolver: R,
    inner: T,
    _phantom: PhantomData<E>,
}

impl<R, T, E> Debug for RustlsAsyncListener<R, T, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsAsyncListener").finish()
    }
}

impl<R, T, E> RustlsAsyncListener<R, T, E>
where
    R: ResolvesServerConfig<E> + Send + 'static,
    T: Listener + Send,
    E: StdError + Send,
{
    /// Create a new `RustlsListener`.
    #[inline]
    pub fn new(config_resolver: R, inner: T) -> Self {
        Self {
            config_resolver,
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<R, T, E> Listener for RustlsAsyncListener<R, T, E>
where
    R: ResolvesServerConfig<E> + Send + 'static,
    T: Listener + Send + 'static,
    T::Acceptor: Send + 'static,
    <T::Acceptor as Acceptor>::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: StdError + Send + 'static,
{
    type Acceptor = RustlsAcceptor<R, T::Acceptor, E>;

    async fn try_bind(self) -> crate::Result<Self::Acceptor> {
        Ok(RustlsAcceptor::new(
            self.config_resolver,
            self.inner.try_bind().await?,
        ))
    }
}

pub struct RustlsAcceptor<R, T, E> {
    config_resolver: R,
    inner: T,
    holdings: Vec<Holding>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    _phantom: PhantomData<E>,
}

impl<R, T, E> Debug for RustlsAcceptor<R, T, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsAcceptor").finish()
    }
}

impl<R, T, E> RustlsAcceptor<R, T, E>
where
    R: ResolvesServerConfig<E> + Send + 'static,
    T: Acceptor + Send + 'static,
    T::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: StdError + Send + 'static,
{
    /// Create a new `RustlsAcceptor`.
    pub fn new(config_resolver: R, inner: T) -> Self {
        let holdings = inner
            .holdings()
            .iter()
            .map(|h| {
                #[allow(unused_mut)]
                let mut versions = h.http_versions.clone();
                #[cfg(feature = "http1")]
                if !versions.contains(&crate::http::Version::HTTP_11) {
                    versions.push(crate::http::Version::HTTP_11);
                }
                #[cfg(feature = "http2")]
                if !versions.contains(&crate::http::Version::HTTP_2) {
                    versions.push(crate::http::Version::HTTP_2);
                }
                Holding {
                    local_addr: h.local_addr.clone(),
                    http_versions: versions,
                    http_scheme: Scheme::HTTPS,
                }
            })
            .collect();
        Self {
            config_resolver,
            inner,
            holdings,
            tls_acceptor: None,
            _phantom: PhantomData,
        }
    }

    /// Get the inner `Acceptor`.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Convert this `RustlsAcceptor` into a boxed `DynTcpAcceptor`.
    pub fn into_boxed(self) -> Box<dyn DynTcpAcceptor> {
        Box::new(ToDynTcpAcceptor(self))
    }
}

impl<R, T, E> Acceptor for RustlsAcceptor<R, T, E>
where
    R: ResolvesServerConfig<E> + Send + 'static,
    T: Acceptor + Send + 'static,
    <T as Acceptor>::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: StdError + Send,
{
    type Coupler = TcpCoupler<Self::Stream>;
    type Stream = HandshakeStream<TlsStream<T::Stream>>;

    fn holdings(&self) -> &[Holding] {
        &self.holdings
    }

    async fn accept(
        &mut self,
        fuse_factory: Option<ArcFuseFactory>,
    ) -> IoResult<Accepted<Self::Coupler, Self::Stream>> {
        let Accepted {
            coupler: _,
            stream,
            fusewire,
            local_addr,
            remote_addr,
            ..
        } = self.inner.accept(fuse_factory).await?;

        let lazy_acceptor = tokio_rustls::LazyConfigAcceptor::new(
            tokio_rustls::rustls::server::Acceptor::default(),
            stream,
        );

        match lazy_acceptor.await {
            Ok(start) => {
                let client_hello: ClientHello = start.client_hello();
                let config_result = self.config_resolver.resolve(client_hello).await;

                match config_result {
                    Ok(config) => {
                        let config: Result<ServerConfig, _> = config.as_ref().clone().try_into();

                        let res = Accepted {
                            coupler: TcpCoupler::new(),
                            stream: HandshakeStream::new(
                                start.into_stream(Arc::new(config?)),
                                fusewire.clone(),
                            ),
                            fusewire,
                            local_addr,
                            remote_addr,
                            http_scheme: Scheme::HTTPS,
                        };

                        return Ok(res);
                    }
                    Err(_err) => {
                        return Err(IoError::new(
                            ErrorKind::Other,
                            "rustls: invalid tls config.",
                        ));
                    }
                }
            }
            Err(_err) => {
                return Err(IoError::new(
                    ErrorKind::Other,
                    "rustls: invalid tls config.",
                ));
            }
        }
    }
}

// impl<S, T, E> Acceptor for RustlsAcceptor<S, T, E>
// where
//     S: ResolvesServerConfig<E> + Send + 'static,
//     T: Acceptor + Send + 'static,
//     <T as Acceptor>::Conn: AsyncRead + AsyncWrite + Send + Unpin + 'static,
//     E: StdError + Send,
// {
//     type Conn = HandshakeStream<TlsStream<T::Conn>>;

//     fn holdings(&self) -> &[Holding] {
//         &self.holdings
//     }

//     async fn accept(
//         &mut self,
//         fuse_factory: Option<ArcFuseFactory>,
//     ) -> IoResult<Accepted<Self::Conn>> {
//         let Accepted {
//             conn,
//             local_addr,
//             remote_addr,
//             ..
//         } = self.inner.accept(fuse_factory).await?;

//         let fusewire = conn.fusewire();

//         let lazy_acceptor =
//             tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), conn);

//         futures_util::pin_mut!(lazy_acceptor);

//         match lazy_acceptor.as_mut().await {
//             Ok(start) => {
//                 let client_hello: ClientHello = start.client_hello();
//                 let config_result = self.config.resolve(client_hello).await;

//                 match config_result {
//                     Ok(config) => {
//                         let config: Result<ServerConfig, _> = config.as_ref().clone().try_into();

//                         if let Err(_err) = config {
//                             return Err(IoError::new(
//                                 ErrorKind::Other,
//                                 "rustls: invalid tls config.",
//                             ));
//                         }

//                         let res: IoResult<Accepted<Self::Conn>> = Ok(Accepted {
//                             conn: HandshakeStream::new(
//                                 start.into_stream(Arc::new(config?)),
//                                 fusewire,
//                             ),
//                             local_addr,
//                             remote_addr,
//                             http_scheme: Scheme::HTTPS,
//                         });

//                         return res;
//                     }
//                     Err(_err) => {
//                         return Err(IoError::new(
//                             ErrorKind::Other,
//                             "rustls: invalid tls config.",
//                         ));
//                     }
//                 }
//             }
//             Err(_err) => {
//                 return Err(IoError::new(
//                     ErrorKind::Other,
//                     "rustls: invalid tls config.",
//                 ));
//             }
//         }
//     }
// }
