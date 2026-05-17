use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TUN_MTU: usize = 1500;

pub async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut transport_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut tun_buf = vec![0u8; TUN_MTU];

    loop {
        tokio::select! {
            result = transport_rx.recv() => {
                match result {
                    Some(data) => {
                        if let Err(e) = tun.write_all(&data).await {
                            return Err(anyhow::anyhow!("Failed to write to TUN: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let data = tun_buf[..n].to_vec();
                        if let Err(e) = tun_tx.send(data).await {
                            return Err(anyhow::anyhow!("Failed to send to transport: {}", e));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Error reading from TUN: {}", e));
                    }
                }
            }
        }
    }
}
