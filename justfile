help:
  just -l

# generate testdata for the Rust tests
testdata:
  forge build
  mkdir -p testdata
  echo $(cat out/StatefulSponge.sol/StatefulSponge.json | jq -r '.deployedBytecode.object' | cut -c3-) > testdata/stateful_sponge

# lint the Rust code
rust-lint: testdata
  cargo +nightly fmt -- && cargo +nightly clippy --all --all-features -- -D warnings

# build the fuzzing tool binary
rust-build: testdata
  cargo build --release

# run the fuzzing tool
rust-fuzz: testdata
  cargo run --release

# run the solidity tests
sol-test:
  forge test -vvv

# build the contracts
sol-build:
  forge build

# lint the contracts
sol-lint:
  forge fmt
