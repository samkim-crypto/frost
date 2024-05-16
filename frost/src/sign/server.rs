use std::fmt::{self, Display, Formatter};

use base64::{prelude::BASE64_STANDARD, Engine};
use curve25519_dalek::{
    digest::{generic_array::typenum::U64, Digest},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;

use crate::sign::{client::*, SignError};

/// The message that the server sends over to the client at round 1 of the distributed signing
/// protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignServerRound1 {
    pub D_server: CompressedEdwardsY,
    pub E_server: CompressedEdwardsY,
}

impl Display for SignServerRound1 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.D_server.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.E_server.as_bytes()))
    }
}

/// The message that the client sends over to the client at around 2 of the distributed signing
/// protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignServerRound2 {
    pub z_server: Scalar,
}

impl Display for SignServerRound2 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.z_server.as_bytes()))
    }
}

pub struct ServerSign;
#[allow(non_snake_case)]
impl ServerSign {
    /// The server logic for the first round of the distributed signing protocol
    ///
    /// It does not matter whether the client or the server starts the protocol first.
    pub fn first_round() -> (Scalar, Scalar, SignServerRound1) {
        // 1. Generates two random scalar elements
        let d_server = Scalar::random(&mut OsRng);
        let e_server = Scalar::random(&mut OsRng);

        // 2. Commits to the two scalar elements above as elliptic curve points
        let D_server = EdwardsPoint::mul_base(&d_server);
        let E_server = EdwardsPoint::mul_base(&e_server);

        // 3. Construct the server's message to the server
        let server_message = SignServerRound1 {
            D_server: D_server.compress(),
            E_server: E_server.compress(),
        };

        (d_server, e_server, server_message)
    }

    /// The server logic for the second round of the distributed signing protocol
    pub fn second_round<CtxDigest>(
        p_server: &Scalar,
        P_joint: &CompressedEdwardsY,
        message: &[u8],
        d_server: &Scalar,
        e_server: &Scalar,
        client_message: &SignClientRound1,
        server_message: &SignServerRound1,
    ) -> Result<(EdwardsPoint, SignServerRound2), SignError>
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        let mut h_client = CtxDigest::new();
        h_client.update(b"client");
        h_client.update(message);
        h_client.update(client_message.D_client.as_bytes());
        h_client.update(client_message.E_client.as_bytes());
        let rho_client = Scalar::from_hash(h_client);

        let mut h_server = CtxDigest::new();
        h_server.update(b"server");
        h_server.update(message);
        h_server.update(server_message.D_server.as_bytes());
        h_server.update(server_message.E_server.as_bytes());
        let rho_server = Scalar::from_hash(h_server);

        let D_client = client_message
            .D_client
            .decompress()
            .ok_or(SignError::Decompression)?;
        let E_client = client_message
            .E_client
            .decompress()
            .ok_or(SignError::Decompression)?;
        let D_server = server_message
            .D_server
            .decompress()
            .ok_or(SignError::Decompression)?;
        let E_server = server_message
            .E_server
            .decompress()
            .ok_or(SignError::Decompression)?;
        let R = D_client + E_client * rho_client + D_server + E_server * rho_server;

        let mut h = CtxDigest::new();
        h.update(R.compress().as_bytes());
        h.update(message);
        h.update(P_joint.as_bytes());
        let c = Scalar::from_hash(h);

        let z_server = d_server + e_server * rho_server - p_server * c;

        let server_message = SignServerRound2 { z_server };
        Ok((R, server_message))
    }

    /// The final step to combine the partial signatures to a full signature
    pub fn combine_sigs<CtxDigest>(
        P_joint: &CompressedEdwardsY,
        P_client: &CompressedEdwardsY,
        message: &[u8],
        client_message_1: &SignClientRound1,
        client_message_2: &SignClientRound2,
        server_message_1: &SignServerRound1,
        server_message_2: &SignServerRound2,
    ) -> Result<(CompressedEdwardsY, Scalar), SignError>
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        let mut h_client = CtxDigest::new();
        h_client.update(b"client");
        h_client.update(message);
        h_client.update(client_message_1.D_client.as_bytes());
        h_client.update(client_message_1.E_client.as_bytes());
        let rho_client = Scalar::from_hash(h_client);

        let D_client = client_message_1
            .D_client
            .decompress()
            .ok_or(SignError::Decompression)?;
        let E_client = client_message_1
            .E_client
            .decompress()
            .ok_or(SignError::Decompression)?;
        let R_client = D_client + E_client * rho_client;

        let mut h_server = CtxDigest::new();
        h_server.update(b"server");
        h_server.update(message);
        h_server.update(server_message_1.D_server.as_bytes());
        h_server.update(server_message_1.E_server.as_bytes());
        let rho_server = Scalar::from_hash(h_server);

        let D_server = server_message_1
            .D_server
            .decompress()
            .ok_or(SignError::Decompression)?;
        let E_server = server_message_1
            .E_server
            .decompress()
            .ok_or(SignError::Decompression)?;
        let R_server = D_server + E_server * rho_server;

        let R = R_client + R_server;
        let mut h = CtxDigest::new();
        h.update(R.compress().as_bytes());
        h.update(message);
        h.update(P_joint.as_bytes());
        let c = Scalar::from_hash(h);

        let expected_1 = EdwardsPoint::mul_base(&client_message_2.z_client);
        let Y_client = P_client.decompress().ok_or(SignError::Decompression)?;
        let expected_2 = R_client + Y_client * c;

        // Verify the server's partial signature
        if expected_1 != expected_2 {
            return Err(SignError::PartialSignatureVerification);
        }

        let R_joint = R.compress();
        let z_joint = client_message_2.z_client + server_message_2.z_server;

        // The final signature is `(R_joint, z_joint)`, which can be encoded as a standard  ed25519
        // signature

        Ok((R_joint, z_joint))
    }
}
