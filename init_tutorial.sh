./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Alice" \
  --genesis \
  --node-port 9400 --rpc-port 9401 --public-port 9402 \
  --documents-dir ./local-demo/node1/documents \
  --config ./local-demo/node1/quorum-trust.toml

./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Bob" \
  --node-port 9410 --rpc-port 9411 --public-port 9412 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node2/documents \
  --config ./local-demo/node2/quorum-trust.toml

./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Carol" \
  --node-port 9420 --rpc-port 9421 --public-port 9422 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node3/documents \
  --config ./local-demo/node3/quorum-trust.toml

./target/release/quorum-trust init \
  --name "local-demo" \
  --display-name "Dave" \
  --node-port 9430 --rpc-port 9431 --public-port 9432 \
  --bootstrap 127.0.0.1:9400 \
  --documents-dir ./local-demo/node4/documents \
  --config ./local-demo/node4/quorum-trust.toml


