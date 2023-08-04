use std::{
    collections::LinkedList,
    sync::{Arc, Mutex},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasmedge_sdk::{async_host_function, error::HostFuncError, Caller, NeverType, WasmValue};

pub struct WasmEdgeHttpsReqModule {
    inner: wasmedge_sdk::ImportObject<NeverType>,
}

#[derive(Debug)]
pub struct WasmEdgeHttpsReqData {
    response: Arc<Mutex<LinkedList<Vec<u8>>>>,
    client_config: Arc<rustls::ClientConfig>,
}

impl WasmEdgeHttpsReqData {
    pub fn new(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            response: Arc::new(Mutex::new(LinkedList::new())),
            client_config,
        }
    }
}

impl Clone for WasmEdgeHttpsReqData {
    fn clone(&self) -> Self {
        Self::new(self.client_config.clone())
    }
}

async fn tls_send(
    client_config: Arc<rustls::ClientConfig>,
    host: Vec<u8>,
    port: u16,
    body: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let host = String::from_utf8(host)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let domain = rustls::ServerName::try_from(host.as_str())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname"))?;
    let addr = (host, port);
    let stream = tokio::net::TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(&body).await?;
    let mut buf = vec![];
    stream.read_to_end(&mut buf).await?;
    Ok(buf)
}

#[async_host_function]
async fn wasmedge_httpsreq_send_data(
    caller: Caller,
    args: Vec<WasmValue>,
    data: &mut WasmEdgeHttpsReqData,
) -> Result<Vec<WasmValue>, HostFuncError> {
    let memory = caller.memory(0).ok_or(HostFuncError::User(1))?;

    // let instance = caller.instance_mut().ok_or(HostFuncError::User(2))?;
    // let data = instance
    //     .host_data::<WasmEdgeHttpsReqData>()
    //     .ok_or(HostFuncError::User(3))?;

    log::trace!("host_data {data:?}");

    if args.len() != 5 {
        return Err(HostFuncError::User(4));
    }

    let host_ptr = args[0].to_i32() as u32;
    let host_len = args[1].to_i32() as u32;
    let port = args[2].to_i32();
    let body_ptr = args[3].to_i32() as u32;
    let body_len = args[4].to_i32() as u32;

    let host = memory
        .read(host_ptr, host_len)
        .or(Err(HostFuncError::User(5)))?;

    let body = memory
        .read(body_ptr, body_len)
        .or(Err(HostFuncError::User(6)))?;

    let resp = tls_send(data.client_config.clone(), host, port as u16, body)
        .await
        .map_err(|_e| HostFuncError::User(7))?;

    if let Ok(mut response) = data.response.lock() {
        response.push_back(resp);
    }

    Ok(vec![])
}

#[async_host_function]
async fn wasmedge_httpsreq_get_rcv_len(
    _caller: Caller,
    _args: Vec<WasmValue>,
    data: &mut WasmEdgeHttpsReqData,
) -> Result<Vec<WasmValue>, HostFuncError> {
    log::trace!("host_data {data:?}");

    if let Ok(response) = data.response.lock() {
        Ok(vec![WasmValue::from_i32(
            response.front().map(|r| r.len() as i32).unwrap_or(0),
        )])
    } else {
        Ok(vec![WasmValue::from_i32(0)])
    }
}

#[async_host_function]
async fn wasmedge_httpsreq_get_rcv(
    caller: Caller,
    args: Vec<WasmValue>,
    data: &mut WasmEdgeHttpsReqData,
) -> Result<Vec<WasmValue>, HostFuncError> {
    log::trace!("host_data {data:?}");

    let mut memory = caller.memory(0).ok_or(HostFuncError::User(1))?;

    if args.len() != 1 {
        return Err(HostFuncError::User(2));
    }
    let recv_ptr = args[0].to_i32() as u32;

    let resp = match data.response.lock() {
        Ok(mut response) => response.pop_front(),
        Err(_) => None,
    };

    if let Some(data) = resp {
        memory
            .write(data, recv_ptr)
            .or(Err(HostFuncError::User(3)))?;
    }

    Ok(vec![])
}

#[allow(deprecated)]
pub fn default_client_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(client_config)
}

// pub struct HTTPsReqData

impl WasmEdgeHttpsReqModule {
    pub fn new(client_config: Arc<rustls::ClientConfig>) -> wasmedge_sdk::WasmEdgeResult<Self> {
        // let data = WasmEdgeHttpsReqData::new(client_config);

        let inner = wasmedge_sdk::ImportObjectBuilder::new()
            .with_async_func::<(i32, i32, i32, i32, i32), (), WasmEdgeHttpsReqData>(
                "wasmedge_httpsreq_send_data",
                wasmedge_httpsreq_send_data,
                Some(Box::new(WasmEdgeHttpsReqData::new(client_config.clone()))),
            )?
            .with_async_func::<(), i32, WasmEdgeHttpsReqData>(
                "wasmedge_httpsreq_get_rcv_len",
                wasmedge_httpsreq_get_rcv_len,
                Some(Box::new(WasmEdgeHttpsReqData::new(client_config.clone()))),
            )?
            .with_async_func::<i32, (), WasmEdgeHttpsReqData>(
                "wasmedge_httpsreq_get_rcv",
                wasmedge_httpsreq_get_rcv,
                Some(Box::new(WasmEdgeHttpsReqData::new(client_config.clone()))),
            )?
            .build::<NeverType>("wasmedge_httpsreq", None)?;

        Ok(Self { inner })
    }
}

impl Into<wasmedge_sdk::ImportObject<NeverType>> for WasmEdgeHttpsReqModule {
    fn into(self) -> wasmedge_sdk::ImportObject<NeverType> {
        self.inner
    }
}
