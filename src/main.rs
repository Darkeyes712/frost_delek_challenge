mod core;
mod frost_error;

use clap::{Arg, Command};
use core::{perform_dkg, perform_threshold_signing};
use frost_error::FrostError;

fn main() -> Result<(), FrostError> {
    let matches = Command::new("Threshold Signature CLI")
        .version("1.0")
        .author("Your Name <you@example.com>")
        .about("Generates threshold signatures using FROST")
        .arg(
            Arg::new("message")
                .help("The message to be signed")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .long("threshold")
                .help("The minimum number of participants required to sign")
                .default_value("2"),
        )
        .arg(
            Arg::new("participants")
                .short('n')
                .long("participants")
                .help("The total number of participants")
                .default_value("3"),
        )
        .get_matches();

    // Retrieve the message to be signed
    let message = matches.get_one::<String>("message").unwrap();
    let message_bytes = message.as_bytes();

    // Retrieve threshold and participants from command line
    let threshold: u32 = matches
        .get_one::<String>("threshold")
        .unwrap()
        .parse()
        .map_err(|_| FrostError::DkgError("Invalid threshold value".into()))?;
    let participants: u32 = matches
        .get_one::<String>("participants")
        .unwrap()
        .parse()
        .map_err(|_| FrostError::DkgError("Invalid participants value".into()))?;

    // Perform Distributed Key Generation
    let (group_key, alice_secret_key, carol_secret_key, params) =
        perform_dkg(threshold, participants)?;

    // Perform Threshold Signing
    perform_threshold_signing(
        alice_secret_key,
        carol_secret_key,
        group_key,
        message_bytes,
        params,
    )?;

    println!(
        "Successfully generated threshold signature for the message: {:?}",
        message
    );
    Ok(())
}
