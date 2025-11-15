mod models;


#[derive(Serialize, Deserialize)]
struct DnsServer {
    address: &str,
    tag: &str
};


#[derive(Serialize, Deserialize)]
struct Dns {
    final: String,
    servers: Vec<Server>
};

#[derive(Serialize, Deserialize)]
struct Inbound {
    address: Vec[String],
    auto_route: bool,
    interface_name: String,
    mtu: i32,
    sniff: bool,
    strict_route: bool,
    tag: str,
    type: str
};

#[derive(Serialize, Deserialize)]
struct Log {
    level: String
};


#[derive(Serialize)]
struct Outbound {
    Direct(DirectOutbound),
    Dns(DnsOutbound),
    Vless(VlessOutbound)
};


#[derive(Serialize, Deserialize)]
pub struct SingBoxConfig {
   dns: Dns,
   inbounds: Vec<Inbound>,
   log: Log,
   outbounds: Vec<Outbound>,
};



