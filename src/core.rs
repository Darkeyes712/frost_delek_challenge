use crate::frost_error::FrostError;

use curve25519_dalek::ristretto::CompressedRistretto;
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists,
    keygen::{GroupKey, IndividualPublicKey, SecretShare},
    DistributedKeyGeneration, IndividualSecretKey, Parameters, Participant, SignatureAggregator,
};
use rand::rngs::OsRng;
use smol_str::{SmolStr, ToSmolStr};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

const DIR: &str = "signature";

// Helper function to ensure the directory exists
fn ensure_directory_exists(dir: &str) -> Result<(), FrostError> {
    if !Path::new(dir).exists() {
        fs::create_dir_all(dir).map_err(FrostError::Io)?;
    }
    Ok(())
}

// Helper function to save the compressed public key
pub fn save_individual_public_key(
    filename: &str,
    key: &IndividualPublicKey,
) -> Result<(), FrostError> {
    let mut file = File::create(filename).map_err(FrostError::Io)?;
    file.write_all(&key.index.to_le_bytes())
        .map_err(FrostError::Io)?;
    let compressed_share = key.share.compress();
    file.write_all(compressed_share.as_bytes())
        .map_err(FrostError::Io)?;
    Ok(())
}

// Helper function to load the compressed public key
pub fn load_individual_public_key(filename: &str) -> Result<IndividualPublicKey, FrostError> {
    let mut file = File::open(filename).map_err(FrostError::Io)?;
    let mut index_bytes = [0u8; 4];
    file.read_exact(&mut index_bytes).map_err(FrostError::Io)?;
    let index = u32::from_le_bytes(index_bytes);
    let mut share_bytes = [0u8; 32];
    file.read_exact(&mut share_bytes).map_err(FrostError::Io)?;
    let compressed_share = CompressedRistretto(share_bytes);
    let share = compressed_share
        .decompress()
        .ok_or(FrostError::DecompressionFailed)?;
    Ok(IndividualPublicKey { index, share })
}

pub fn save_secret_shares(filename: &str, shares: &[SecretShare]) -> Result<(), FrostError> {
    let mut file = File::create(filename).map_err(FrostError::Io)?;
    for share in shares {
        share.serialize(&mut file).map_err(FrostError::Io)?;
    }
    Ok(())
}

pub fn load_secret_shares(filename: &str) -> Result<Vec<SecretShare>, FrostError> {
    let mut file = File::open(filename).map_err(FrostError::Io)?;
    let mut shares = Vec::new();

    while let Ok(share) = SecretShare::deserialize(&mut file) {
        shares.push(share);
    }

    Ok(shares)
}

pub fn perform_dkg(
    t: u32,
    n: u32,
) -> Result<
    (
        GroupKey,
        IndividualSecretKey,
        IndividualSecretKey,
        Parameters,
    ),
    FrostError,
> {
    ensure_directory_exists(DIR)?; // Ensure the directory exists

    let params = Parameters { t, n };

    // Create participants and their coefficients
    let (alice, alice_coefficients) = Participant::new(&params, 1);
    let (bob, bob_coefficients) = Participant::new(&params, 2);
    let (carol, carol_coefficients) = Participant::new(&params, 3);

    // Start DKG Round One for all participants
    let alice_state = DistributedKeyGeneration::<_>::new(
        &params,
        &alice.index,
        &alice_coefficients,
        &mut vec![bob.clone(), carol.clone()],
    )
    .map_err(|e| FrostError::DkgError(format!("Could not acquire Alice's state: {e:?}").into()))?;

    let bob_state = DistributedKeyGeneration::<_>::new(
        &params,
        &bob.index,
        &bob_coefficients,
        &mut vec![alice.clone(), carol.clone()],
    )
    .map_err(|e| FrostError::DkgError(format!("Could not acquire Bob's state: {e:?}").into()))?;

    let carol_state = DistributedKeyGeneration::<_>::new(
        &params,
        &carol.index,
        &carol_coefficients,
        &mut vec![alice.clone(), bob.clone()],
    )
    .map_err(|e| FrostError::DkgError(format!("Could not acquire Carol's state: {e:?}").into()))?;

    // Save secret shares directly after creating them
    let share_filenames = [
        format!("{}/1_secret_share.bin", DIR),
        format!("{}/2_secret_share.bin", DIR),
        format!("{}/3_secret_share.bin", DIR),
    ];

    // Save Alice's secret shares
    let alice_my_secret_shares = vec![
        bob_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Bob's shares: {e:?}").into())
        })?[0]
            .clone(),
        carol_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Carol's shares: {e:?}").into())
        })?[0]
            .clone(),
    ];
    save_secret_shares(&share_filenames[0], &alice_my_secret_shares)?;

    // Save Bob's secret shares
    let bob_my_secret_shares = vec![
        alice_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Alice's shares: {e:?}").into())
        })?[0]
            .clone(),
        carol_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Carol's shares: {e:?}").into())
        })?[1]
            .clone(),
    ];
    save_secret_shares(&share_filenames[1], &bob_my_secret_shares)?;

    // Save Carol's secret shares
    let carol_my_secret_shares = vec![
        alice_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Alice's shares: {e:?}").into())
        })?[1]
            .clone(),
        bob_state.their_secret_shares().map_err(|e| {
            FrostError::DkgError(format!("Could not acquire Bob's shares: {e:?}").into())
        })?[1]
            .clone(),
    ];
    save_secret_shares(&share_filenames[2], &carol_my_secret_shares)?;

    // Load secret shares directly without looping
    let alice_shares = load_secret_shares(&share_filenames[0])?;
    let bob_shares = load_secret_shares(&share_filenames[1])?;
    let carol_shares = load_secret_shares(&share_filenames[2])?;

    // Transition to Round Two for each participant
    let states_round_two = [
        alice_state
            .to_round_two(alice_shares)
            .map_err(|_| FrostError::RoundTwoError)?,
        bob_state
            .to_round_two(bob_shares)
            .map_err(|_| FrostError::RoundTwoError)?,
        carol_state
            .to_round_two(carol_shares)
            .map_err(|_| FrostError::RoundTwoError)?,
    ];

    // Finish the DKG process and derive keys
    let (alice_group_key, alice_secret_key) = states_round_two[0]
        .clone()
        .finish(
            alice
                .public_key()
                .ok_or_else(|| FrostError::DkgError("Alice's public key not found".into()))?,
        )
        .map_err(|e| {
            FrostError::DkgError(format!("Error finishing DKG for Alice: {:?}", e).into())
        })?;

    let (bob_group_key, bob_secret_key) = states_round_two[1]
        .clone()
        .finish(
            bob.public_key()
                .ok_or_else(|| FrostError::DkgError("Bob's public key not found".into()))?,
        )
        .map_err(|e| {
            FrostError::DkgError(format!("Error finishing DKG for Bob: {:?}", e).into())
        })?;

    let (carol_group_key, carol_secret_key) = states_round_two[2]
        .clone()
        .finish(
            carol
                .public_key()
                .ok_or_else(|| FrostError::DkgError("Carol's public key not found".into()))?,
        )
        .map_err(|e| {
            FrostError::DkgError(format!("Error finishing DKG for Carol: {:?}", e).into())
        })?;

    // Verify the group keys are the same
    assert_eq!(alice_group_key, bob_group_key);
    assert_eq!(bob_group_key, carol_group_key);

    // Generate public keys
    let alice_public_key = alice_secret_key.to_public();
    let bob_public_key = bob_secret_key.to_public();
    let carol_public_key = carol_secret_key.to_public();

    // Save public keys to disk
    save_individual_public_key(&format!("{}/1_public_key.bin", DIR), &alice_public_key)?;
    save_individual_public_key(&format!("{}/2_public_key.bin", DIR), &bob_public_key)?;
    save_individual_public_key(&format!("{}/3_public_key.bin", DIR), &carol_public_key)?;

    Ok((alice_group_key, alice_secret_key, bob_secret_key, params))
}

/// Perform threshold signing using loaded public keys and secret shares
pub fn perform_threshold_signing(
    rnd_participant_1_secret_key: IndividualSecretKey,
    rnd_participant_2_secret_key: IndividualSecretKey,
    group_key: GroupKey,
    message: &[u8],
    params: Parameters,
) -> Result<(), FrostError> {
    // Load public keys
    let rnd_participant_1_public_key =
        load_individual_public_key(&format!("{}/1_public_key.bin", DIR))?;
    let rnd_participant_2_public_key =
        load_individual_public_key(&format!("{}/2_public_key.bin", DIR))?;

    // Generate commitment share lists for the signers
    let (rnd_participant_1_public_comshares, mut rnd_participant_1_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 1, 1);
    let (rnd_participant_2_public_comshares, mut rnd_participant_2_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 2, 1);

    let context = b"CONTEXT SmolStr FOR SIGNING";
    let message_hash = compute_message_hash(&context[..], message);

    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], message);

    // Include signers using public keys and commitment shares
    aggregator.include_signer(
        1, // Participant 1
        rnd_participant_1_public_comshares.commitments[0],
        rnd_participant_1_public_key,
    );
    aggregator.include_signer(
        2, // Participant 2
        rnd_participant_2_public_comshares.commitments[0],
        rnd_participant_2_public_key,
    );

    // Generate partial signatures using the secret keys
    let rnd_participant_1_partial = rnd_participant_1_secret_key
        .sign(
            &message_hash,
            &group_key,
            &mut rnd_participant_1_secret_comshares,
            0,
            aggregator.get_signers(),
        )
        .map_err(|e| FrostError::SigningError(e.to_smolstr()))?;

    let rnd_participant_2_partial = rnd_participant_2_secret_key
        .sign(
            &message_hash,
            &group_key,
            &mut rnd_participant_2_secret_comshares,
            0,
            aggregator.get_signers(),
        )
        .map_err(|e| FrostError::SigningError(e.to_smolstr()))?;

    // Include partial signatures in the aggregator
    aggregator.include_partial_signature(rnd_participant_1_partial);
    aggregator.include_partial_signature(rnd_participant_2_partial);

    // Finalize the aggregator and handle the result
    let final_signature_result = aggregator.finalize();

    match final_signature_result {
        Ok(aggregated) => {
            let final_signature = aggregated.aggregate().map_err(|e| {
                let error_details: SmolStr = e
                    .iter()
                    .map(|x| x.1.to_smolstr())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .into();
                FrostError::SigningError(error_details)
            })?;
            let signature_bytes = final_signature.to_bytes();
            println!("Final Threshold Signature (Bytes): {:?}", signature_bytes);
            let signature_hex = hex::encode(signature_bytes);
            println!("Final Threshold Signature (Hex): {}", signature_hex);
        }
        Err(errors) => {
            println!("Failed to finalize the aggregator. Issues encountered:");
            for (index, error) in errors {
                println!("Participant {}: {}", index, error);
            }
        }
    }

    Ok(())
}
