pub mod dkg;
pub mod sign;

#[cfg(test)]
mod tests {
    use crate::dkg::{client::*, server::*};
    use crate::sign::{client::*, server::*};
    use curve25519_dalek::EdwardsPoint;
    use sha2::Sha512;

    #[allow(non_snake_case)]
    #[test]
    pub fn test_correctness() {
        // mpc distributed key generation
        let (c0, c1, C0, C1, client_dkg_message_1) = ClientDkg::start_first_round::<Sha512>();
        let (s0, s1, S0, S1, server_dkg_message_1) = ServerDkg::start_first_round::<Sha512>();

        ServerDkg::finalize_first_round::<Sha512>(&client_dkg_message_1).unwrap();
        ClientDkg::finalize_first_round::<Sha512>(&server_dkg_message_1).unwrap();

        let (c_client, client_dkg_message_2) = ClientDkg::start_second_round(&c0, &c1);
        let (s_server, server_dkg_message_2) = ServerDkg::start_second_round(&s0, &s1);

        let (p_client, P_client_1, P_server_1, P_joint_1) = ClientDkg::finalize_second_round(
            &c_client,
            &C0,
            &C1,
            &server_dkg_message_1,
            &server_dkg_message_2,
        )
        .unwrap();

        let (p_server, P_server_2, P_client_2, P_joint_2) = ServerDkg::finalize_second_round(
            &s_server,
            &S0,
            &S1,
            &client_dkg_message_1,
            &client_dkg_message_2,
        )
        .unwrap();

        // make sure that client and server ends up with the same public keys
        assert_eq!(P_client_1.compress(), P_client_2.compress());
        assert_eq!(P_server_1.compress(), P_server_2.compress());
        assert_eq!(P_joint_1.compress(), P_joint_2.compress());

        // make sure that the client and server's private keys are valid
        assert_eq!(
            EdwardsPoint::mul_base(&p_client).compress(),
            P_client_1.compress()
        );
        assert_eq!(
            EdwardsPoint::mul_base(&p_server).compress(),
            P_server_1.compress()
        );
        let p_joint = p_client + p_server;
        assert_eq!(
            EdwardsPoint::mul_base(&p_joint).compress(),
            P_joint_1.compress()
        );

        // mpc signing
        let P_joint = P_joint_1.compress();
        let P_client = P_client_1.compress();
        let P_server = P_server_1.compress();
        let message = b"sample message";

        let (d_client, e_client, client_sign_message_1) = ClientSign::first_round();
        let (d_server, e_server, server_sign_message_1) = ServerSign::first_round();

        let (R_1, client_sign_message_2) = ClientSign::second_round::<Sha512>(
            &p_client,
            &P_joint,
            message,
            &d_client,
            &e_client,
            &client_sign_message_1,
            &server_sign_message_1,
        )
        .unwrap();

        let (R_2, server_sign_message_2) = ServerSign::second_round::<Sha512>(
            &p_server,
            &P_joint,
            message,
            &d_server,
            &e_server,
            &client_sign_message_1,
            &server_sign_message_1,
        )
        .unwrap();

        assert_eq!(R_1.compress(), R_2.compress());

        let (R_1_post, z_1) = ClientSign::combine_sigs::<Sha512>(
            &P_joint,
            &P_server,
            message,
            &client_sign_message_1,
            &client_sign_message_2,
            &server_sign_message_1,
            &server_sign_message_2,
        )
        .unwrap();

        let (R_2_post, z_2) = ServerSign::combine_sigs::<Sha512>(
            &P_joint,
            &P_client,
            message,
            &client_sign_message_1,
            &client_sign_message_2,
            &server_sign_message_1,
            &server_sign_message_2,
        )
        .unwrap();

        assert_eq!(R_1.compress(), R_1_post);
        assert_eq!(R_1_post, R_2_post);
        assert_eq!(z_1, z_2);
    }
}
