
use lessvless::models::{Route,SingBoxConfig};

mod tests {
    use super::*;

    #[test]
    fn test_deserialize_route() -> Result<(), Box<dyn std::error::Error>> {
        
        let rule_str = r#"{
                "auto_detect_interface": true,
                "default_domain_resolver": "cloudflare-doh",
                "final": "aboba",
                "rules": [
                    {
                        "outbound": "dns-out",
                        "protocol": "dns"
                    },
                    {
                        "ip_cidr": [
                            "10.0.0.0/8",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "100.64.0.0/10",
                            "127.0.0.0/8",
                            "::1/128",
                            "fc00::/7",
                            "fe80::/10"
                        ],
                        "outbound": "direct-out"
                    },
                    {
                        "domain_suffix": [
                            "lan",
                            "local",
                            "home"
                        ],
                        "outbound": "direct-out"
                    }
                ]
        }"#;

        let expected_route: Route = serde_json::from_str(rule_str)?;

        Ok(())
    }


    #[test]
    fn test_deserialize_config() -> Result<(), Box<dyn std::error::Error>> {
        
        let rule_str = r#"
            {
              "dns": {
                "final": "cloudflare-doh",
                "servers": [
                  {
                    "address": "local",
                    "tag": "system"
                  },
                  {
                    "address": "https://1.1.1.1/dns-query",
                    "tag": "cloudflare-doh"
                  }
                ]
              },
              "inbounds": [
                {
                  "address": [
                    "172.16.0.1/30"
                  ],
                  "auto_route": true,
                  "interface_name": "tun10",
                  "mtu": 1500,
                  "sniff": true,
                  "strict_route": true,
                  "tag": "tun-in",
                  "type": "tun"
                },
                {
                  "listen": "127.0.0.1",
                  "listen_port": 7890,
                  "sniff": true,
                  "tag": "mixed-in",
                  "type": "mixed"
                }
              ],
              "log": {
                "level": "info"
              },
              "outbounds": [
                {
                  "tag": "direct-out",
                  "type": "direct"
                },
                {
                  "tag": "dns-out",
                  "type": "dns"
                },
                {
                  "packet_encoding": "xudp",
                  "server": "example_server",
                  "server_port": 8080,
                  "tag": "wh3tduwc",
                  "tls": {
                    "enabled": true,
                    "reality": {
                      "enabled": true,
                      "public_key": "example_public_key",
                      "short_id": "example_short_id"
                    },
                    "server_name": "example_server_name.ru",
                    "utls": {
                      "enabled": true,
                      "fingerprint": "chrome"
                    }
                  },
                  "type": "vless",
                  "uuid": "example_uuid"
                }
              ],
              "route": {
                "auto_detect_interface": true,
                "default_domain_resolver": "cloudflare-doh",
                "final": "wh3tduwc",
                "rules": [
                  {
                    "outbound": "dns-out",
                    "protocol": "dns"
                  },
                  {
                    "ip_cidr": [
                      "10.0.0.0/8",
                      "172.16.0.0/12",
                      "192.168.0.0/16",
                      "100.64.0.0/10",
                      "127.0.0.0/8",
                      "::1/128",
                      "fc00::/7",
                      "fe80::/10"
                    ],
                    "outbound": "direct-out"
                  },
                  {
                    "domain_suffix": [
                      "lan",
                      "local",
                      "home"
                    ],
                    "outbound": "direct-out"
                  }
                ]
              }

        }"#;

        let expected_route: SingBoxConfig = serde_json::from_str(rule_str)?;

        Ok(())
    }
}
