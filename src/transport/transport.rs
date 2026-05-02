use crate::codec::Message;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

pub trait TransportTrait {
    type Error;

    fn send(
        &mut self,
        msg: Message,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + '_>>;

    fn next(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<Result<(Message, SocketAddr), Self::Error>>> + Send + '_>>;
}
