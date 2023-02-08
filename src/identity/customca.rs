use super::CertificateProvider;
use async_trait::async_trait;
use kube::{
    api::{Api, PostParams, ListParams, WatchEvent},
    client::Client,
};
use tracing::{instrument, warn};
use crate::{identity::manager::Identity, tls::SanChecker};
use crate::identity::Error;
use crate::tls;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::{api::certificates::v1::{CertificateSigningRequest, CertificateSigningRequestSpec}, ByteString};
use std::str;
use rand::prelude::*;

#[derive(Clone)]
pub struct CustomSigner {
    pub signer: Option<std::string::String>,
}

impl CustomSigner {
    pub fn new(signer: Option<std::string::String>) -> Result<CustomSigner, Error> {
        Ok(CustomSigner { signer })
    }
}

#[async_trait]
impl CertificateProvider for CustomSigner {
    #[instrument(skip_all)]
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        let client: Client = Client::try_default()
        .await
        .expect("Expected a valid KUBECONFIG environment variable.");
        let csr: Api<CertificateSigningRequest> = Api::all(client.clone());
        let pp = PostParams::default();
        let cs = tls::CsrOptions {
            san: id.to_string(),
        }
        .generate()?;
        let cert: Vec<u8> = cs.csr;
        let pkey = cs.pkey;
        let csr_name = generate_csr_name();
        let stored_csr_name = csr_name.clone();
        let signer_name = &self.signer;
        let mut usage = Vec::new();
        usage.push("client auth".to_string());

        let obj_metadata = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta{
            name: Some(csr_name),
            ..Default::default()
        };
        let csr_spec = CertificateSigningRequestSpec{
            expiration_seconds:Some(86400),
            request:k8s_openapi::ByteString(cert),
            signer_name:signer_name.as_ref().unwrap().to_string(),
            usages:Some(usage),
            ..Default::default()
        };

        let csr_req = CertificateSigningRequest {
            metadata: obj_metadata,
            spec: csr_spec,
            ..Default::default()
        };

        // creating CSR
        match csr.create(&pp, &csr_req).await {
            Ok(o) => {
                let name = o.metadata.name.unwrap_or_default();
                assert_eq!(csr_req.metadata.name.unwrap_or_default(), name);
            }
            Err(kube::Error::Api(ae)) => assert_eq!(ae.code, 409),
            Err(_) => return Err(Error::EmptyResponse(id.clone()))?
        };

        let final_certs = check_signed_cert(&csr, &stored_csr_name).await;
        let res_certs : tls::Certs;
        match final_certs {
            Ok(cert_chain) => {
                let cert_chain_vec = cert_chain.0;
                let final_cert_chain = vec![str::from_utf8(&cert_chain_vec).unwrap()];
                let leaf = final_cert_chain[0].as_bytes();
                let final_chain = if final_cert_chain.len() > 1 {
                    final_cert_chain[1..].iter().map(|final_cert_chain| final_cert_chain.as_bytes()).collect()
                } else {
                    warn!("no chain certs for: {}", id);
                    vec![]
                };
                res_certs = tls::cert_from(&pkey, leaf, final_chain);
                res_certs
                .verify_san(id)
                .map_err(|_| Error::SanError(id.clone()))?;
                return Ok(res_certs);
            },
            Err(_) => return Err(Error::EmptyResponse(id.clone()))?,
        }
    }
}

fn generate_csr_name() -> String{
    let mut rng = thread_rng();
    let rand_number: u16 = rng.gen();
    let rand_string = rand_number.to_string();
    let base_string = "csr-ztunnel-";
    format!("{}{}", base_string, rand_string)
}

async fn check_signed_cert(csr: &Api<CertificateSigningRequest>, csr_name: &String) -> Result<k8s_openapi::ByteString, anyhow::Error> {
    let lp = ListParams::default().fields(&format!("{}{}", "metadata.name=", csr_name)).timeout(30);
    let mut stream = csr.watch(&lp, "0").await?.boxed();
    let res :std::option::Option<ByteString>;
    while let Some(status) = stream.try_next().await? {
        match status {
            WatchEvent::Added(o) => {
                println!("Added {}", o.metadata.name.unwrap_or_default());
            }
            WatchEvent::Modified(o) => {
                let s = o.status.as_ref().expect("status exists on csr");
                if s.certificate.is_some() {
                    println!("Certificate signed for {}", o.metadata.name.unwrap_or_default());
                    res = s.certificate.clone();
                    return Ok(res.unwrap_or_default());
                }
            }
            _ => {}
        }
    }
    Err(anyhow::Error::msg("Signer is unable to sign the certificate"))
}