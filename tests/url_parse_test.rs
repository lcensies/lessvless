use lessvless::url_parser::parse_url;
use serde_json::Map;

mod tests {
    use super::*;  

    #[test]
    fn test_parse_url() -> Result<(), Box<dyn std::error::Error>> {
        let url = "vless://host.tld:443?param1=value1&param2=value2".to_string();
        let json: Map<String, serde_json::Value> = parse_url(&url)?; 
        // Assert protocol
        assert_eq!(json.get("protocol").unwrap(), "vless");

        // Assert hostname
        assert_eq!(json.get("host").unwrap(), "host.tld");

        // Assert port
        assert_eq!(json.get("port").unwrap(), 443);

        // Assert parameters
        let params = json.get("params").unwrap().as_object().unwrap();
        assert_eq!(params.get("param1").unwrap(), "value1");
        assert_eq!(params.get("param2").unwrap(), "value2");
    
        Ok(())        

    }
}
