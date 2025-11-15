use crate::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// STUN server for WebRTC NAT traversal
/// Compatible with iris-client which uses Google and Cloudflare STUN servers
pub struct StunServer {
    addr: SocketAddr,
    socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
}

impl StunServer {
    /// Create a new STUN server
    /// Default port is 3478 (standard STUN port)
    pub fn new() -> Result<Self> {
        let addr = "0.0.0.0:3478".parse().map_err(|e| {
            crate::Error::Generic(format!("Failed to parse STUN server address: {}", e))
        })?;

        Ok(Self {
            addr,
            socket: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a STUN server with custom address
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self {
            addr,
            socket: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the STUN server
    pub async fn start(&self) -> Result<()> {
        let socket = UdpSocket::bind(self.addr).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to bind STUN server: {}", e))
        })?;

        info!("STUN server started on {}", self.addr);
        let socket = Arc::new(socket);
        *self.socket.write().await = Some(socket.clone());

        // Spawn the STUN server task
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            Self::run_server(socket_clone).await;
        });

        Ok(())
    }

    async fn run_server(socket: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 2048];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    debug!("STUN: Received {} bytes from {}", len, peer_addr);

                    // Parse STUN message
                    if let Err(e) = Self::handle_stun_message(&socket, &buf[..len], peer_addr).await {
                        error!("STUN: Error handling message: {}", e);
                    }
                }
                Err(e) => {
                    error!("STUN: Error receiving data: {}", e);
                }
            }
        }
    }

    async fn handle_stun_message(
        socket: &Arc<UdpSocket>,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Basic STUN message parsing
        // STUN message format: [type(2)][length(2)][magic(4)][transaction_id(12)]

        if data.len() < 20 {
            return Err("STUN message too short".into());
        }

        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_length = u16::from_be_bytes([data[2], data[3]]);
        let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // STUN magic cookie should be 0x2112A442
        if magic_cookie != 0x2112A442 {
            return Err("Invalid STUN magic cookie".into());
        }

        // Transaction ID (12 bytes)
        let transaction_id = &data[8..20];

        debug!(
            "STUN: Message type: 0x{:04x}, length: {}, from: {}",
            msg_type, msg_length, peer_addr
        );

        // Handle binding request (0x0001)
        if msg_type == 0x0001 {
            Self::send_binding_response(socket, transaction_id, peer_addr).await?;
        }

        Ok(())
    }

    async fn send_binding_response(
        socket: &Arc<UdpSocket>,
        transaction_id: &[u8],
        peer_addr: SocketAddr,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Build STUN Binding Success Response (0x0101)
        let mut response = Vec::new();

        // Message Type: Binding Success Response (0x0101)
        response.extend_from_slice(&0x0101u16.to_be_bytes());

        // We'll calculate the length later
        let length_pos = response.len();
        response.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie
        response.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID (12 bytes)
        response.extend_from_slice(transaction_id);

        // Add XOR-MAPPED-ADDRESS attribute (0x0020)
        // This is the main attribute that tells the client their public IP/port
        let xor_mapped_addr = Self::build_xor_mapped_address(peer_addr, transaction_id);
        response.extend_from_slice(&xor_mapped_addr);

        // Update length field (message length excluding 20-byte header)
        let msg_length = (response.len() - 20) as u16;
        response[length_pos..length_pos + 2].copy_from_slice(&msg_length.to_be_bytes());

        // Send response
        socket.send_to(&response, peer_addr).await?;
        debug!("STUN: Sent binding response to {}", peer_addr);

        Ok(())
    }

    fn build_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8]) -> Vec<u8> {
        let mut attr = Vec::new();

        // Attribute Type: XOR-MAPPED-ADDRESS (0x0020)
        attr.extend_from_slice(&0x0020u16.to_be_bytes());

        // Attribute Length (will be set later)
        let length_pos = attr.len();
        attr.extend_from_slice(&0u16.to_be_bytes());

        // Reserved (1 byte) + Family (1 byte)
        attr.push(0x00); // Reserved

        match addr {
            SocketAddr::V4(v4) => {
                attr.push(0x01); // IPv4 family

                // XOR Port (port XOR with most significant 16 bits of magic cookie)
                let port = v4.port();
                let xor_port = port ^ 0x2112;
                attr.extend_from_slice(&xor_port.to_be_bytes());

                // XOR Address (IPv4 address XOR with magic cookie)
                let ip_bytes = v4.ip().octets();
                let magic_bytes = 0x2112A442u32.to_be_bytes();
                for i in 0..4 {
                    attr.push(ip_bytes[i] ^ magic_bytes[i]);
                }

                // Attribute length is 8 bytes for IPv4 (1 reserved + 1 family + 2 port + 4 address)
                attr[length_pos..length_pos + 2].copy_from_slice(&8u16.to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                attr.push(0x02); // IPv6 family

                // XOR Port
                let port = v6.port();
                let xor_port = port ^ 0x2112;
                attr.extend_from_slice(&xor_port.to_be_bytes());

                // XOR Address (IPv6 address XOR with magic cookie + transaction ID)
                let ip_bytes = v6.ip().octets();
                let mut xor_key = Vec::new();
                xor_key.extend_from_slice(&0x2112A442u32.to_be_bytes());
                xor_key.extend_from_slice(transaction_id);

                for i in 0..16 {
                    attr.push(ip_bytes[i] ^ xor_key[i]);
                }

                // Attribute length is 20 bytes for IPv6 (1 reserved + 1 family + 2 port + 16 address)
                attr[length_pos..length_pos + 2].copy_from_slice(&20u16.to_be_bytes());
            }
        }

        attr
    }

    /// Get the STUN server address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop the STUN server
    pub async fn stop(&self) {
        *self.socket.write().await = None;
        info!("STUN server stopped");
    }
}
