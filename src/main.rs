use std::{borrow::Cow, sync::Arc};

use connections::{ProtocolVersion, StreamConnection};
use environment_server::EnvironmentServer;
use mock_env::MockEnv;
use tokio::net::TcpListener;

mod connections;
mod defs;
mod environment;
mod environment_server;
mod handle;
mod messages;
mod mock_env;
mod server;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let listener = TcpListener::bind("0.0.0.0:52736").await.unwrap();
    log::info!("Listening on {}", listener.local_addr().unwrap());

    let environment = Box::new(MockEnv::new());
    let server = Arc::new(EnvironmentServer::new(environment));

    loop {
        log::info!("Waiting for a connection..");

        let (stream, sockaddr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => return Err(err.into()),
        };
        stream.set_nodelay(true).unwrap();

        log::info!("Client connected from {}", sockaddr);
        let connection_id = sockaddr.to_string();

        let mut client = StreamConnection::new(
            Box::new(stream),
            server.clone(),
            ProtocolVersion::Ver5,
            Some(connection_id),
        );

        tokio::spawn(async move {
            let result = client.serve().await;
            log::info!("Client closed connection: {:?}", result);
        });
    }
}
