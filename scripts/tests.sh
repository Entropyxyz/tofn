#!/bin/bash

# Runs all the tests, should stay up to day with the CI pipeline tests.
# (e.g. if you add tests to the CI pipeline, or this file, reflect those changes accordingly)

cargo test --release --all-features
cargo test --test integration -- multi_thread
cargo test --all-features --test integration -- multi_thread
cargo test --test integration -- single_thread
cargo test --all-features --test integration -- single_thread
