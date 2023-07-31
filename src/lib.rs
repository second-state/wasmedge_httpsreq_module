use std::{
    collections::LinkedList,
    sync::{Arc, Mutex},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasmedge_sdk::{error::HostFuncError, CallingFrame, WasmValue};

pub struct WasmEdgeHttpsReqModule {
    inner: wasmedge_sdk::ImportObject<WasmEdgeHttpsReqData>,
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

fn wasmedge_httpsreq_send_data(
    calling_frame: CallingFrame,
    params: Vec<WasmValue>,
    host_data: *mut std::ffi::c_void,
) -> Box<dyn std::future::Future<Output = Result<Vec<WasmValue>, HostFuncError>> + Send> {
    log::trace!("host_data {host_data:p}");
    let host_data = unsafe { (host_data as *mut WasmEdgeHttpsReqData).as_mut() };
    Box::new(async move {
        let data = match host_data {
            Some(data) => data,
            None => {
                log::error!("host_data is none");
                return Err(HostFuncError::User(2));
            }
        };

        let memory = calling_frame.memory_mut(0).ok_or(HostFuncError::User(1))?;
        if let [host_ptr, host_len, port, body_ptr, body_len] = &params[..] {
            let host_ptr = host_ptr.to_i32() as u32;
            let host_len = host_len.to_i32() as u32;
            let port = port.to_i32();
            let body_ptr = body_ptr.to_i32() as u32;
            let body_len = body_len.to_i32() as u32;

            let host = memory
                .get_data(host_ptr, host_len)
                .or(Err(HostFuncError::User(1)))?;

            let body = memory
                .get_data(body_ptr, body_len)
                .or(Err(HostFuncError::User(1)))?;

            let resp = tls_send(data.client_config.clone(), host, port as u16, body)
                .await
                .map_err(|_e| HostFuncError::User(3))?;

            if let Ok(mut response) = data.response.lock() {
                response.push_back(resp);
            }

            Ok(vec![])
        } else {
            Err(HostFuncError::User(2))
        }
    })
}

fn wasmedge_httpsreq_get_rcv_len(
    _calling_frame: CallingFrame,
    _params: Vec<WasmValue>,
    host_data: *mut std::ffi::c_void,
) -> Box<dyn std::future::Future<Output = Result<Vec<WasmValue>, HostFuncError>> + Send> {
    log::trace!("host_data {host_data:p}");

    let host_data = unsafe { (host_data as *mut WasmEdgeHttpsReqData).as_mut() };

    Box::new(async move {
        let data = match host_data {
            Some(data) => data,
            None => {
                log::error!("host_data is none");
                return Err(HostFuncError::User(2));
            }
        };

        if let Ok(response) = data.response.lock() {
            Ok(vec![WasmValue::from_i32(
                response.front().map(|r| r.len() as i32).unwrap_or(0),
            )])
        } else {
            Ok(vec![WasmValue::from_i32(0)])
        }
    })
}

fn wasmedge_httpsreq_get_rcv(
    calling_frame: CallingFrame,
    params: Vec<WasmValue>,
    host_data: *mut std::ffi::c_void,
) -> Box<dyn std::future::Future<Output = Result<Vec<WasmValue>, HostFuncError>> + Send> {
    log::trace!("host_data {host_data:p}");

    let host_data = unsafe { (host_data as *mut WasmEdgeHttpsReqData).as_mut() };

    Box::new(async move {
        let data = match host_data {
            Some(data) => data,
            None => {
                log::error!("host_data is none");
                return Err(HostFuncError::User(2));
            }
        };

        let mut memory = calling_frame.memory_mut(0).ok_or(HostFuncError::User(1))?;
        if let [recv_ptr] = &params[..] {
            let recv_ptr = recv_ptr.to_i32() as u32;

            let resp = if let Ok(mut response) = data.response.lock() {
                response.pop_front()
            } else {
                None
            };

            if let Some(resp) = resp {
                memory
                    .set_data(resp, recv_ptr)
                    .or(Err(HostFuncError::User(1)))?;
            }

            Ok(vec![])
        } else {
            Err(HostFuncError::User(2))
        }
    })
}

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

impl WasmEdgeHttpsReqModule {
    pub fn new(client_config: Arc<rustls::ClientConfig>) -> wasmedge_sdk::WasmEdgeResult<Self> {
        let data = Box::new(WasmEdgeHttpsReqData::new(client_config));
        let inner = wasmedge_sdk::ImportObjectBuilder::new()
            .with_host_data(data)
            .with_async_func::<(i32, i32, i32, i32, i32), ()>(
                "wasmedge_httpsreq_send_data",
                wasmedge_httpsreq_send_data,
            )?
            .with_async_func::<(), i32>(
                "wasmedge_httpsreq_get_rcv_len",
                wasmedge_httpsreq_get_rcv_len,
            )?
            .with_async_func::<i32, ()>("wasmedge_httpsreq_get_rcv", wasmedge_httpsreq_get_rcv)?
            .build("wasmedge_httpsreq")?;
        Ok(Self { inner })
    }
}

impl Into<wasmedge_sdk::ImportObject<WasmEdgeHttpsReqData>> for WasmEdgeHttpsReqModule {
    fn into(self) -> wasmedge_sdk::ImportObject<WasmEdgeHttpsReqData> {
        self.inner
    }
}
