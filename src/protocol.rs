use crate::model::*;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 65536;
const MAX_ADMIN_RESPONSE: usize = 4 * 1024 * 1024;
pub const VERSION: u16 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub version: u16,
    pub token: String,
    pub name: String,
    pub identity_id: String,
    pub attempt_id: String,
    pub public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EnrollmentResponse {
    Welcome(Welcome),
    Error { message: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    Activate {
        version: u16,
        agent_id: String,
        attempt_id: String,
    },
    Sync {
        version: u16,
        agent_id: String,
        applied_generation: u64,
        error: Option<String>,
    },
    Ban {
        version: u16,
        agent_id: String,
        forward_id: u64,
        ip: std::net::IpAddr,
        ttl_seconds: u64,
    },
    RotateKey {
        version: u16,
        agent_id: String,
        rotation_id: String,
        public_key: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Active { generation: u64 },
    Policy(AgentPolicy),
    RotateRequested { rotation_id: String },
    RotateCommitted { generation: u64 },
    Ok,
    Error { message: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminRequest {
    Status,
    AgentsList,
    AgentsShow {
        name: String,
    },
    Invite {
        name: String,
        ttl_seconds: u64,
    },
    CancelInvite {
        name: String,
    },
    AgentRemove {
        name: String,
    },
    AgentDisable {
        name: String,
    },
    AgentEnable {
        name: String,
    },
    AgentRename {
        name: String,
        new_name: String,
    },
    AgentRotate {
        name: String,
    },
    ForwardsList,
    ForwardAdd(Forward),
    ForwardRemove {
        id: u64,
    },
    ForwardEnable {
        id: u64,
        enabled: bool,
    },
    Ban {
        agent: String,
        forward_id: u64,
        ip: std::net::IpAddr,
        ttl_seconds: u64,
    },
    BansList,
    Reload,
    Logs {
        lines: usize,
    },
    VpnPeerAdd {
        name: String,
    },
    VpnPeerList,
    VpnPeerEnable {
        name: String,
        enabled: bool,
    },
    VpnPeerRevoke {
        name: String,
    },
    VpnAllow {
        peer: String,
        agent: String,
        access: VpnAccess,
    },
    /// Without `access`, removes every grant of the peer on that agent.
    VpnDeny {
        peer: String,
        agent: String,
        access: Option<VpnAccess>,
    },
    VpnConfig {
        name: String,
    },
    /// Whether the web panel is on, where it listens and which devices may open it.
    PanelStatus,
    PanelPassword,
    /// Whether two-factor panel login is on, and its mode.
    PanelTwoFactorStatus,
    /// Creates a pending secret to scan; `PanelTwoFactorConfirm` turns the login factor on.
    PanelTwoFactorSetup,
    PanelTwoFactorConfirm {
        code: String,
    },
    /// Deletes the secret and ends all panel sessions.
    PanelTwoFactorReset,
    /// Let a VPN device open the web panel, or withdraw that again.
    PanelAllow {
        name: String,
        allowed: bool,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
}
impl AdminResponse {
    pub fn success(data: impl Serialize) -> Self {
        Self {
            ok: true,
            data: serde_json::to_value(data).unwrap_or_default(),
            error: None,
        }
    }
    pub fn error(error: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            data: serde_json::Value::Null,
            error: Some(error.to_string()),
        }
    }
}
pub async fn send<T: Serialize, W: AsyncWrite + Unpin>(stream: &mut W, value: &T) -> Result<()> {
    send_limited(stream, value, MAX_FRAME).await
}
async fn send_limited<T: Serialize, W: AsyncWrite + Unpin>(
    stream: &mut W,
    value: &T,
    limit: usize,
) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    ensure!(data.len() <= limit, "message exceeds protocol size limit");
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}
pub async fn receive<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<T> {
    receive_limited(stream, MAX_FRAME).await
}
async fn receive_limited<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(
    stream: &mut R,
    limit: usize,
) -> Result<T> {
    let len = stream.read_u32().await? as usize;
    ensure!(len > 0 && len <= limit, "invalid message size");
    let mut data = vec![0; len];
    stream.read_exact(&mut data).await?;
    Ok(serde_json::from_slice(&data)?)
}
pub async fn send_admin<W: AsyncWrite + Unpin>(
    stream: &mut W,
    value: &AdminResponse,
) -> Result<()> {
    send_limited(stream, value, MAX_ADMIN_RESPONSE).await
}
pub async fn receive_admin<R: AsyncRead + Unpin>(stream: &mut R) -> Result<AdminResponse> {
    receive_limited(stream, MAX_ADMIN_RESPONSE).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_oversized_frames_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(8);
        a.write_u32(MAX_FRAME as u32 + 1).await.unwrap();
        assert!(receive::<AdminRequest, _>(&mut b).await.is_err());
    }
    #[tokio::test]
    async fn large_local_status_does_not_expand_the_public_frame_limit() {
        let (mut sender, mut receiver) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            send_admin(
                &mut sender,
                &AdminResponse::success("x".repeat(MAX_FRAME + 1)),
            )
            .await
            .unwrap();
        });
        let response = receive_admin(&mut receiver).await.unwrap();
        assert!(response.ok);
        assert!(response.data.as_str().unwrap().len() > MAX_FRAME);
        writer.await.unwrap();
    }
}
