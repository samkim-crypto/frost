use std::fmt::{self, Display, Formatter};

use base64::{prelude::BASE64_STANDARD, Engine};
use curve25519_dalek::{
    digest::{generic_array::typenum::U64, Digest},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;

use crate::dkg::{
    server::{DkgServerRound1, DkgServerRound2},
    DkgError,
};

/// The message that the client sends over to the server at round 1 of the distributed key
/// generation protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DkgClientRound1 {
    pub C0: CompressedEdwardsY,
    pub C1: CompressedEdwardsY,
    pub R: CompressedEdwardsY,
    pub mu: Scalar,
}

impl Display for DkgClientRound1 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.C0.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.C1.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.R.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.mu.as_bytes()))
    }
}

/// The message that the client sends over to the server at round 1 of the distributed key
/// generation protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DkgClientRound2 {
    pub c_server: Scalar,
}

impl Display for DkgClientRound2 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.c_server.as_bytes()))
    }
}

pub struct ClientDkg;
#[allow(non_snake_case)]
impl ClientDkg {
    /// The client logic that starts the first round of the distributed key generation protocol
    ///
    /// It does not matter whether the client or the server starts the protocol first.
    pub fn start_first_round<CtxDigest>(
    ) -> (Scalar, Scalar, EdwardsPoint, EdwardsPoint, DkgClientRound1)
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        // 1. Generates two random scalar elements
        let c0 = Scalar::random(&mut OsRng);
        let c1 = Scalar::random(&mut OsRng);

        // 2. Commits to the two scalar elements above as elliptic curve points
        let C0 = EdwardsPoint::mul_base(&c0);
        let C1 = EdwardsPoint::mul_base(&c1);

        // 3. Create a proof of knowledge of `c0` over `C0`
        let k = Scalar::random(&mut OsRng);
        let R = EdwardsPoint::mul_base(&k);

        let mut h = CtxDigest::new();
        h.update(b"client");
        h.update(C0.compress().as_bytes());
        h.update(R.compress().as_bytes());
        let c = Scalar::from_hash(h);
        let mu = k + c0 * c;

        // 4. Construct the client's message to the server
        let client_message = DkgClientRound1 {
            C0: C0.compress(),
            C1: C1.compress(),
            R: R.compress(),
            mu,
        };

        (c0, c1, C0, C1, client_message)
    }

    /// The client logic that verifies the server's message in the first round of the distributed
    /// key generation protocol
    pub fn finalize_first_round<CtxDigest>(server_message: &DkgServerRound1) -> Result<(), DkgError>
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        let DkgServerRound1 { S0, S1: _, R, mu } = server_message;

        // verify the server's proof of knowledge
        let mut h = CtxDigest::new();
        h.update(b"server");
        h.update(S0.as_bytes());
        h.update(R.as_bytes());
        let c = Scalar::from_hash(h);

        let S0 = S0.decompress().ok_or(DkgError::Decompression)?;
        let expected_R = EdwardsPoint::mul_base(mu) + S0 * (-c);
        if *R != expected_R.compress() {
            return Err(DkgError::ProofOfKnowledge);
        }

        Ok(())
    }

    /// The client logic that starts the second round of the distributed key generation protocol
    pub fn start_second_round(c0: &Scalar, c1: &Scalar) -> (Scalar, DkgClientRound2) {
        let c_client = c0 + c1;
        let c_server = c0 - c1;
        let client_message = DkgClientRound2 { c_server };

        (c_client, client_message)
    }

    /// The client logic that verifies the server's message in the second round of the distributed
    /// key generation protocol
    pub fn finalize_second_round(
        c_client: &Scalar,
        C0: &EdwardsPoint,
        C1: &EdwardsPoint,
        server_message_1: &DkgServerRound1,
        server_message_2: &DkgServerRound2,
    ) -> Result<(Scalar, EdwardsPoint, EdwardsPoint, EdwardsPoint), DkgError> {
        // 1. Verify that the server provided the correct share from its randomly generated scalar
        let S0 = server_message_1.S0.decompress().unwrap();
        let S1 = server_message_1.S1.decompress().unwrap();

        let S_client = S0 + S1;
        let expected_S_client = EdwardsPoint::mul_base(&server_message_2.s_client);

        if S_client.compress() != expected_S_client.compress() {
            return Err(DkgError::ShareVerification);
        }

        // 2. Finalize the private and public key shares

        // Create client's private key share
        let p_client = c_client + server_message_2.s_client;

        // Create client's public key share
        let P_client = EdwardsPoint::mul_base(&p_client);

        // Create server's public key share
        let P_server = C0 - C1 + S0 - S1;

        // Create the joint public key
        let P_joint = P_client + P_server;

        Ok((p_client, P_client, P_server, P_joint))
    }
}
