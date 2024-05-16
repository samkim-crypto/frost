use std::fmt::{self, Display, Formatter};

use base64::{prelude::BASE64_STANDARD, Engine};
use curve25519_dalek::{
    digest::{generic_array::typenum::U64, Digest},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;

use crate::dkg::{
    client::{DkgClientRound1, DkgClientRound2},
    DkgError,
};

/// The message that the server sends over to the client at round 1 of the distributed key
/// generation protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DkgServerRound1 {
    pub S0: CompressedEdwardsY,
    pub S1: CompressedEdwardsY,
    pub R: CompressedEdwardsY,
    pub mu: Scalar,
}

impl Display for DkgServerRound1 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.S0.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.S1.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.R.as_bytes()))?;
        write!(f, "{}", BASE64_STANDARD.encode(self.mu.as_bytes()))
    }
}

/// The message that the server sends over to the client at round 2 of the distributed key
/// generation protocol
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DkgServerRound2 {
    pub s_client: Scalar,
}

impl Display for DkgServerRound2 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.s_client.as_bytes()))
    }
}

pub struct ServerDkg;
#[allow(non_snake_case)]
impl ServerDkg {
    /// The client logic that starts the first round of the distributed key generation protocol
    ///
    /// It does not matter whether the client or the server starts the protocol first.
    pub fn start_first_round<CtxDigest>(
    ) -> (Scalar, Scalar, EdwardsPoint, EdwardsPoint, DkgServerRound1)
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        // 1. Generates two random scalar elements
        let s0 = Scalar::random(&mut OsRng);
        let s1 = Scalar::random(&mut OsRng);

        // 2. Commits to the two scalar elements above as elliptic curve points
        let S0 = EdwardsPoint::mul_base(&s0);
        let S1 = EdwardsPoint::mul_base(&s1);

        // 3. Create a proof of knowledge of `s0` over `S0`
        let k = Scalar::random(&mut OsRng);
        let R = EdwardsPoint::mul_base(&k);

        let mut h = CtxDigest::new();
        h.update(b"server");
        h.update(S0.compress().as_bytes());
        h.update(R.compress().as_bytes());
        let c = Scalar::from_hash(h);
        let mu = k + s0 * c;

        // 4. Construct the server's message to the client
        let server_message = DkgServerRound1 {
            S0: S0.compress(),
            S1: S1.compress(),
            R: R.compress(),
            mu,
        };

        (s0, s1, S0, S1, server_message)
    }

    /// The server logic that verifies the server's message in the first round of the distributed
    /// key generation protocol
    pub fn finalize_first_round<CtxDigest>(client_message: &DkgClientRound1) -> Result<(), DkgError>
    where
        CtxDigest: Digest<OutputSize = U64>,
    {
        let DkgClientRound1 { C0, C1: _, R, mu } = client_message;

        // verify the client's proof of knowledge
        let mut h = CtxDigest::new();
        h.update(b"client");
        h.update(C0.as_bytes());
        h.update(R.as_bytes());
        let c = Scalar::from_hash(h);

        let C0 = C0.decompress().unwrap();
        let expected_R = EdwardsPoint::mul_base(mu) + C0 * (-c);
        if *R != expected_R.compress() {
            return Err(DkgError::ProofOfKnowledge);
        }

        Ok(())
    }

    /// The server logic that starts the second round of the distributed key generation protocol
    pub fn start_second_round(s0: &Scalar, s1: &Scalar) -> (Scalar, DkgServerRound2) {
        let s_client = s0 + s1;
        let s_server = s0 - s1;
        let server_message = DkgServerRound2 { s_client };

        (s_server, server_message)
    }

    /// The client logic that verifies the client's message in the second round of the distributed
    /// key generation protocol
    pub fn finalize_second_round(
        s_server: &Scalar,
        S0: &EdwardsPoint,
        S1: &EdwardsPoint,
        client_message_1: &DkgClientRound1,
        client_message_2: &DkgClientRound2,
    ) -> Result<(Scalar, EdwardsPoint, EdwardsPoint, EdwardsPoint), DkgError> {
        // 1. Verify that the client provided the correct share from its randomly generated scalar
        let C0 = client_message_1.C0.decompress().unwrap();
        let C1 = client_message_1.C1.decompress().unwrap();

        let C_server = C0 - C1;
        let expected_C_server = EdwardsPoint::mul_base(&client_message_2.c_server);

        if C_server.compress() != expected_C_server.compress() {
            return Err(DkgError::ShareVerification);
        }

        // 2. Finalize the private and public key shares

        // Create server's private key share
        let p_server = client_message_2.c_server + s_server;

        // Create server's public key share
        let P_server = EdwardsPoint::mul_base(&p_server);

        // Create client's public key share
        let P_client = C0 + C1 + S0 + S1;

        // Create the joint public key
        let P_joint = P_client + P_server;

        Ok((p_server, P_server, P_client, P_joint))
    }
}
