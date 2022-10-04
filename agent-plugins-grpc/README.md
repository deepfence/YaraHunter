# Agent plugins gRPC

This repository contains all the schema used by plugins to communicate with the probe agent.

## Go (ThreatMapper)

Run the Makefile located in this repository to generate all the gRPC go files:

```
make go
```

## Rust (open-tracer)

For Rust, we recommend to use `cargo` directly. Create a `build.rs` file alongside your `Cargo.toml`.
Then add the following:

```
tonic_build::configure()
.build_server(true)
    .compile(
             &[
             "proto/common.proto",
             "proto/agent_plugin.proto",
             "proto/kernel_tracer.proto",
             "proto/open_tracer.proto",
             ],
             &["proto"],
            )?;
Ok(())
```

In your project `Cargo.toml`:
```
tonic = "0.6"
prost = "0.9"
futures = "0.3.19"
```

In your source code, you can start using protobuf output by including it like:

```
pub mod proto {
    pub mod common {
        tonic::include_proto!("common");
    }
    pub mod kernel_tracer {
        tonic::include_proto!("kernel_tracer");
    }
    pub mod agent_plugin {
        tonic::include_proto!("agent_plugin");
    }
    pub mod open_tracer {
        tonic::include_proto!("open_tracer");
    }
}
```
