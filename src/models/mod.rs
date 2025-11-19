use serde::{Serialize, Deserialize};
use serde::Deserializer;
use std::collections::HashMap;
use derivative::Derivative;
use std::fs::File;
use crate::url_parser::parse_url;
use std::error::Error;
use serde_json::{Map,Value};

pub mod models;


#[derive(Serialize, Deserialize, Derivative, Debug, Clone)]
#[derivative(Default)]
pub struct DnsServer {
    #[derivative(Default(value="String::from(\"default\")"))]
    address: String,
    tag: String,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Clone, Default)]
pub struct Dns {
    #[serde(rename = "final")]
    #[derivative(Default(value="String::from(\"default\")"))]
    final_field: String,
    servers: Vec<DnsServer>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sniff: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_route: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strict_route: Option<bool>,
    tag: String,
    #[serde(rename = "type")]
    type_field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stack: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Log {
    level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<bool>,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Clone)]
#[derivative(Default)]
pub struct DirectOutbound {
    tag: String,
    #[serde(rename = "type")]
    #[derivative(Default(value="String::from(\"direct\")"))]
    type_field: String,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Clone)]
#[derivative(Default)]
pub struct SocksOutbound {
    tag: String,
    #[serde(rename = "type")]
    #[derivative(Default(value="String::from(\"socks\")"))]
    type_field: String,
    server: String,
    server_port: i32,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Clone)]
#[derivative(Default)]
pub struct DnsOutbound {
    tag: String,
    #[serde(rename = "type")]
    #[derivative(Default(value="String::from(\"dns\")"))]
    type_field: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealityConfig {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    short_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UtlsConfig {
    enabled: bool,
    fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsConfig {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<RealityConfig>,
    server_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    utls: Option<UtlsConfig>,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Clone)]
#[derivative(Default)]
pub struct VlessOutbound {
    packet_encoding: String,
    server: String,
    server_port: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(rename = "type")]
    #[derivative(Default(value="String::from(\"vless\")"))]
    type_field: String,
    tag: String,
    uuid: String
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum Outbound {
    Direct(DirectOutbound),
    Dns(DnsOutbound),
    Vless(VlessOutbound),
}
impl Outbound {
    fn deserialize_outbound<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a HashMap to access fields dynamically
        let map: HashMap<String, serde_json::Value> = Deserialize::deserialize(deserializer)?;


        let type_str: &str = map.get("type").unwrap_or_default().as_str().unwrap_or("direct");
        let tag = map.get("tag").ok_or_else(|| serde::de::Error::missing_field("tag"))?;

        match type_str {
            "direct" => {
                let direct_outbound = DirectOutbound {
                    tag: tag.as_str().unwrap().to_string(),
                    type_field: type_str.to_string()
                };
                Ok(Outbound::Direct(direct_outbound))
            }
            "dns" => {

                let dns_outbound: DnsOutbound = serde_json::from_value(serde_json::json!(map)).map_err(serde::de::Error::custom)?;
                Ok(Outbound::Dns(dns_outbound))
            }
            "vless" => {
                let uuid = map.get("uuid")
                    .unwrap_or(&serde_json::Value::String("default_uuid".to_string()))
                    .as_str().unwrap_or("default_encoding").to_string();
                let packet_encoding = map.get("packet_encoding")
                    .unwrap_or(&serde_json::Value::String("default_encoding".to_string()))
                    .as_str().unwrap_or("default_encoding").to_string();

                let server = map.get("server")
                    .unwrap_or(&serde_json::Value::String("default_server".to_string()))
                    .as_str().unwrap_or("default_server").to_string();

                let server_port = map.get("server_port")
                    .and_then(|v| v.as_i64())
                    .map(|p| p as i32)
                    .unwrap_or(8080); // Default port

                let tls = map.get("tls").and_then(|tls_value| {
                    serde_json::from_value(tls_value.clone()).ok()
                });
                let vless_outbound = VlessOutbound {
                    tag: tag.to_string(),
                    packet_encoding,
                    server,
                    server_port,
                    type_field: "vless".to_string(), 
                    tls: tls,
                    uuid: uuid
                };
                Ok(Outbound::Vless(vless_outbound))
            }
            _ => Err(serde::de::Error::custom(format!("unknown type: {}", type_str))),
        }
    }
}

impl<'de> Deserialize<'de> for Outbound {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize_outbound(deserializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RouteRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    inbound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outbound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_cidr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_suffix: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_is_private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_name: Option<Vec<String>>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Route {
    auto_detect_interface: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_domain_resolver: Option<String>,
    #[serde(rename = "final")]
    #[serde(skip_serializing_if = "Option::is_none")]
    final_field: Option<String>,
    rules: Vec<RouteRule>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingBoxConfig {
    dns: Dns,
    inbounds: Vec<Inbound>,
    log: Log,
    outbounds: Vec<Outbound>,
    route: Route
}

impl VlessOutbound {
    fn enrich(&mut self, root_params: Map<String, Value>) {
        self.server = root_params.get("host").unwrap_or_default().to_string();
        self.server_port = root_params.get("port").unwrap_or_default().as_i64().expect("Incorrect port specified") as i32;
        self.uuid = root_params.get("uuid").unwrap_or_default().to_string();
        let params = root_params.get("params").unwrap_or_default();

        let mut tls = TlsConfig {
            enabled: true,
            reality: None,
            server_name: String::new(),
            utls: None,
        };
        
        if let Some(security) = params.get("security") {
            match security {
                Value::String(s) if s == "reality" => {
                    let reality = RealityConfig {
                        enabled: true,
                        public_key: Some(params
                            .get("pbk")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_default()),
                        short_id: params
                            .get("sid")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    };
                    tls.reality = Some(reality);
                }
                _ => todo!(),
            }
        }

        if let Some(sni) = params.get("sni") {
            if let Some(s) = sni.as_str() {
                tls.server_name = s.to_string();
            }
        } 

        if let Some(fp) = params.get("fp") {
            if let Some(s) = fp.as_str() {
                tls.utls = Some(UtlsConfig {
                    enabled: true,
                    fingerprint: s.to_string(),
                });
            }
        }

        self.tls = Some(tls);
    }
}

impl SingBoxConfig {
    pub fn from_file(path: String) -> Option<SingBoxConfig> {
        let file = File::open(path).expect("Failed to open sing-box config");
       serde_json::from_reader(file).expect("Failed to parse sing-box json file")
    }

    fn get_vless_outbound(&mut self) -> VlessOutbound {
        let existing_out = self.outbounds.iter().find(|out| match out {
            Outbound::Vless(_) => true,
            _ => false
        });

        return match existing_out {
            Some(out) => match out {
                Outbound::Vless(vless) => vless.clone(),
                _ => unreachable!(),
            },
            None => {
                let default_out = VlessOutbound::default();
                self.outbounds.push(Outbound::Vless(default_out.clone()));
                default_out
            }
        };
    }

    fn update_vless_outbound(&mut self, vless: VlessOutbound) {
        let vless_out_idx: usize = self.outbounds.iter().position(|out| matches!(out, Outbound::Vless(_))).unwrap();
        assert!(vless_out_idx > 0, "Vless outbound is not present");

        self.outbounds[vless_out_idx] = Outbound::Vless(vless);
    }
    
    pub fn enrich_from_url(&mut self, url: String) -> Result<Self, Box<dyn Error>> {
        let params: Map<String, Value> = parse_url(&url)?;
        let protocol = params.get("protocol").expect("Failed to parse protocol").as_str().expect("Failed to get protocol from URL");
        let _outbound = match protocol {
            "vless" => {
                let mut vless = self.get_vless_outbound();
                vless.enrich(params);
                self.update_vless_outbound(vless); 
            } 
            _ => {
                println!("Unknown protocol: {:?}", protocol);
                todo!()
            }
        };
         
        Ok(self.clone())
    }

    pub fn enrich_from_dns(&mut self, dns: String) -> Result<Self, Box<dyn Error>> {
        let non_local_server = self.dns.servers.iter_mut().find(|s| s.address != "local");
        if let Some(server) = non_local_server {
            server.address = dns;
        } else {
            let mut new_dns = DnsServer::default();
            new_dns.address = dns;
            self.dns.servers.push(new_dns);
        }
        Ok(self.clone())
    }
}
