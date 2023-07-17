use wasmedge_sdk::config::{CommonConfigOptions, ConfigBuilder, HostRegistrationConfigOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let file_name = std::env::args().nth(1).unwrap();

    let config = ConfigBuilder::new(CommonConfigOptions::default())
        .with_host_registration_config(HostRegistrationConfigOptions::default().wasi(true))
        .build()?;

    let import =
        wasmedge_httpsreq::WasmEdgeHttpsReqModule::new(wasmedge_httpsreq::default_client_config())?;

    let async_state = wasmedge_sdk::r#async::AsyncState::new();
    wasmedge_sdk::VmBuilder::new()
        .with_config(config)
        .build()
        .unwrap()
        .register_import_module(import.into())?
        .run_func_from_file_async(&async_state, file_name, "_start", vec![])
        .await
        .unwrap();

    Ok(())
}
