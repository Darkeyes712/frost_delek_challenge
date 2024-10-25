# Threshold Signature CLI

## Overview

This repository contains a command-line interface (CLI) application for generating threshold signatures using the FROST (Flexible Round-Optimized Schnorr Threshold) protocol. It allows users to perform Distributed Key Generation (DKG) and threshold signing in a secure manner, utilizing cryptographic techniques to ensure that a group of participants can jointly sign a message without requiring any single participant to hold the complete signing key.

## Features

- **Distributed Key Generation**: Participants can collaboratively generate a group key and individual secret keys through a secure protocol.
- **Threshold Signing**: Only a specified minimum number of participants are required to create a valid signature for a given message.
- **Error Handling**: Comprehensive error handling using custom error types for better debugging and user feedback.

## Prerequisites

Ensure that you have the following installed on your machine:

- Rust
- Cargo (comes with Rust)

## Installation

1. Clone the repository:

    ```bash
    git clone <https://github.com/Darkeyes712/frost_delek_challenge>
    cd <frost_delek_challenge>
    ```

2. Build the project:

    ```bash
    cargo build
    ```

3. Run the application:

    ```bash
    cargo run "Some message"
    ```

## Usage

The CLI accepts the following arguments:

- `message`: The message to be signed (required).

To see all available commands and options, run:

```bash
cargo run -- --help
```

## Code Structure

- **core.rs**: Contains the core logic for Distributed Key Generation and threshold signing. It handles the file I/O operations for saving and loading public keys and secret shares, and it manages the state transitions during the signing process.

- **frost_error.rs**: Defines custom error types using the `thiserror` crate to provide meaningful error messages throughout the application.

- **main.rs**: The entry point of the application, setting up the CLI interface using `clap` and orchestrating the overall workflow, including user input and command handling.

## Error Handling

The application uses custom error types defined in `frost_error.rs` to handle various error scenarios. This includes I/O errors, decompression failures, errors during key generation, and signing issues. Comprehensive error handling improves the user experience and aids in debugging.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

The code in this repository implements a command-line application that facilitates the generation of threshold signatures using the FROST protocol. It allows users to specify a message for signing, as well as the minimum number of participants required to validate a signature and the total number of participants involved in the signing process.

The main functionalities include:

- **Distributed Key Generation**: Participants use the application to collaboratively generate a group key and their respective secret keys in a secure manner, ensuring that no single participant has access to the entire key.

- **Threshold Signing**: Once the keys are generated, specified participants can sign a given message, creating a valid signature that can be verified by others, enhancing security and resilience against failures.

- **Error Handling**: The application includes robust error handling to capture and report various issues during execution, ensuring that users receive informative feedback.
