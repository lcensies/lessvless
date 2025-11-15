use lessvless::url_parser::parse_url;
use lessvless::models::SingBoxConfig;
use lessvless::utils::find_git_root; 
use serde_json::Map;

mod tests {
    use super::*;  

    #[test]
    fn test_enrich_from_url() -> Result<(), Box<dyn std::error::Error>> {
        let url = "vless://host.tld:443?security=reality&encryption=none&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&pbk=iBXtaHGkwadJMtkWYZxMRfqLLAuDvTHKsHQiLFXXJniM&sni=www.microsoft.com&sid=some-sid".to_string();
        let config_path = find_git_root()?.canonicalize().unwrap().join("config").join("default.json").to_str().unwrap().to_string();
        // println!("{:?}", config_path);
        let default_config = SingBoxConfig::from_file(config_path).unwrap();

        let new_config = default_config.clone().enrich_from_url(url);

    
        Ok(())        

    }
}
