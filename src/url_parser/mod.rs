pub mod url_parser;

use regex::Regex;
use std::error::Error;
use std::str::FromStr;
use serde_json::{Value, Map};


#[derive(Debug, Clone)]
struct ParseError(String);

impl ParseError {
    fn new(msg: &str) -> Self {
        ParseError(msg.to_string())
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ParseError {}

impl From<regex::Error> for ParseError {
    fn from(e: regex::Error) -> Self {
        ParseError::new(&format!("Regex error: {}", e))
    }
}

pub fn parse_url_params(params: String) -> Result<Map<String, Value>, Box<dyn Error>> {
    let mut map = Map::new();
    
    for param in params.split("&") {
        let parts: Vec<&str> = param.split("=").collect();
        
        if parts.len() != 2 {
            return Err(Box::new(ParseError::new("Invalid parameter format")));
        }
        
        let (key, value) = (parts[0], parts[1]);
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
    
    Ok(map)
}

pub fn parse_url(url: &String) -> Result<Map<String, Value>, Box<dyn Error>> {
    let mut dict = Map::new();
    let url_regex = Regex::new(r"([a-z+]+)://([a-z0-9\-]+)@([a-z0-9]+(?:\.[a-z0-9]+)*):(\d+)(?:\?(.*))?")
    .expect("Invalid regex pattern");
    let captures = url_regex.captures(url).expect("Failed to parse URL");
    
    if captures.len() != 6 {
        return Err(ParseError::new(format!("Wrong number of captures, expected 5: {:?}", captures).as_str()).into());
    }

    let protocol: String = captures.get(1)
        .map(|m| m.as_str())
        .ok_or(ParseError::new("Failed to parse protocol"))?
        .to_string();
    let uuid: String = captures.get(2)
        .map(|m| m.as_str())
        .ok_or(ParseError::new("Failed to parse uuid"))?
        .to_string();
    let host : String = captures.get(3)
        .map(|m| m.as_str())
        .ok_or(ParseError::new("Failed to parse host"))?
        .to_string();
    let port : String = captures.get(4)
        .map(|m| m.as_str())
        .ok_or(ParseError::new("Failed to parse host"))?
        .to_string();
    let params: String = captures.get(5)
        .map(|m| m.as_str())
        .ok_or(ParseError::new("Failed to parse URL params"))?
        .to_string();

    
    dict.insert("protocol".to_string(), Value::String(protocol));
    dict.insert("host".to_string(), Value::String(host));
    dict.insert("port".to_string(), Value::Number(serde_json::Number::from_str(port.as_str()).unwrap()));
    dict.insert("params".to_string(), Value::Object(parse_url_params(params.to_string()).unwrap()));

    Ok(dict)
}



