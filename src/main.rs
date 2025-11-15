mod lessvless;

use models::SingBoxConfig;
use std::fs;


fn main() {
    let file = fs::File::open("/etc/sing-box/config.json").expect("Failed to open sing-box config");
    let json: SingBoxConfig = serde_json::from_reader(file).expect("Failed to parse sing-box json file");
    println!("Finished");
}
