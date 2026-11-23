//! Length-prefixed (unsigned varint) protobuf framing over a libp2p stream.

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for a single message; certificate chains are a few KiB.
pub const MAX_MESSAGE: usize = 256 * 1024;

pub async fn write<M: prost::Message, S: AsyncWrite + Unpin>(io: &mut S, msg: &M) -> io::Result<()> {
    io.write_all(&msg.encode_length_delimited_to_vec()).await?;
    io.flush().await
}

pub async fn read<M: prost::Message + Default, S: AsyncRead + Unpin>(io: &mut S) -> io::Result<M> {
    let mut len: u64 = 0;
    for shift in (0..64).step_by(7) {
        let mut b = [0u8];
        io.read_exact(&mut b).await?;
        len |= u64::from(b[0] & 0x7f) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
    }
    let len = usize::try_from(len).map_err(|_| invalid("length overflow"))?;
    if len > MAX_MESSAGE {
        return Err(invalid("message too large"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    M::decode(buf.as_slice()).map_err(|e| invalid(&e.to_string()))
}

/// One request/response exchange as the dialer; closes our write side after the request.
pub async fn call<Req, Resp, S>(io: &mut S, req: &Req) -> io::Result<Resp>
where
    Req: prost::Message,
    Resp: prost::Message + Default,
    S: AsyncRead + AsyncWrite + Unpin,
{
    write(io, req).await?;
    let resp = read(io).await?;
    let _ = io.close().await;
    Ok(resp)
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Dns01Request, IssueInfo};

    #[test]
    fn roundtrip() {
        futures::executor::block_on(async {
            let msg = Dns01Request { fqdn: "x".repeat(300), value: "v".into() };
            let mut buf = futures::io::Cursor::new(Vec::new());
            write(&mut buf, &msg).await.unwrap();
            write(&mut buf, &IssueInfo { domain: "d".into(), ..Default::default() }).await.unwrap();
            buf.set_position(0);
            assert_eq!(read::<Dns01Request, _>(&mut buf).await.unwrap(), msg);
            assert_eq!(read::<IssueInfo, _>(&mut buf).await.unwrap().domain, "d");
        });
    }
}
