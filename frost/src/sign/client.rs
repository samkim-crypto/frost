use std::fmt::{self, Display, Formatter};

use base64::{prelude::BASE64_STANDARD, Engine};
use curve25519_dalek::{
    digest::{generic_array::typenum::U64, Digest},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;

use crate::sign::{server::*, SignError};

/// The message that the client sends over to the server at round 1 of the distributed signing
/// protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignClientRound1 {
    pub D_client: CompressedEdwardsY,
    pub E_client: CompressedEdwardsY,
}

impl Display for SignClientRound1 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.D_client.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.E_client.as_bytes()))
    }
}

/// The message that the client sends over to the server at round 2 of the distributed signing
/// protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignClientRound2 {
    pub z_client: Scalar,
}

impl Display for SignClientRound2 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.z_client.as_bytes()))
    }
}

pub struct ClientSign;
#[allow(non_snake_case)]
impl ClientSign {
    /// The client logic for the first round of the distributed signing protocol
    ///
    /// It does not matter whether the client or the server starts the protocol first.
    pub fn first_round() -> (Scalar, Scalar, SignClientRound1) {
        // 1. Generates two random scalar elements
        let d_client = Scalar::random(&mut OsRng);
        let e_client = Scalar::random(&mut OsRng);

        // 2. Commits to the two scalar elements above as elliptic curve points
        let D_client = EdwardsPoint::mul_base(&d_client);
        let E_client = EdwardsPoint::mul_base(&e_client);

        // 3. Construct the client's message to the server
        let client_message = SignClientRound1 {
            D_client: D_client.compress(),
            E_client: E_client.compress(),
        };

        (d_client, e_client, client_message)
    }

    /// The client logic for the second round of the distributed signing protocol
    pub fn second_round<CtxDigest>(
        p_client: &Scalar,
        P_joint: &CompressedEdwardsY,
        message: &[u8],
        d_client: &Scalar,
        e_client: &Scalar,
        client_message: &SignClientRound1,
        server_message: &SignServerRound1,
    ) -> Result<(EdwardsPoint, SignClientRound2), SignError>
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

        let z_client = d_client + e_client * rho_client + p_client * c;

        let client_message = SignClientRound2 { z_client };
        Ok((R, client_message))
    }

    /// The final step to combine the partial signatures to a full signature
    pub fn combine_sigs<CtxDigest>(
        P_joint: &CompressedEdwardsY,
        P_server: &CompressedEdwardsY,
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

        let partial_signature_1 = EdwardsPoint::mul_base(&server_message_2.z_server);
        let Y_server = P_server.decompress().ok_or(SignError::Decompression)?;
        let partial_signature_2 = R_server - Y_server * c;

        // Verify the server's partial signature
        if partial_signature_1 != partial_signature_2 {
            return Err(SignError::PartialSignatureVerification);
        }

        let R_joint = R.compress();
        let z_joint = client_message_2.z_client + server_message_2.z_server;

        // The final signature is `(R_joint, z_joint)`, which can be encoded as a standard  ed25519
        // signature

        Ok((R_joint, z_joint))
    }
}
