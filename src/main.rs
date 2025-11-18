use lessvless::models::SingBoxConfig;
use std::fs::File;
use clap::Parser;
use std::io::Write;


#[derive(Parser)]
struct Args {
    #[clap(long = "config")]
    config: String,

    #[clap(long = "url")]
    url: Option<String>,

    #[clap(long = "dns")]
    dns: Option<String>,
    
    #[clap(long = "output")]
    output: Option<String>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let default_config = SingBoxConfig::from_file(args.config).unwrap();
    let mut new_config: SingBoxConfig = default_config.clone();
    
    if let Some(url) = args.url {
        new_config.enrich_from_url(url).unwrap();
    }
    if let Some(dns) = args.dns {
        new_config.enrich_from_dns(dns).unwrap();
    }

    let mut json_data = serde_json::to_string_pretty(&new_config)?;  
    json_data = json_data.replace("\\\"", "");
    
    if let Some(output) = args.output {
        let mut file = File::create(output)?;
        file.write_all(json_data.as_bytes())?;
    } else {
        println!("{}", json_data);
    }
     

    Ok(())
}
