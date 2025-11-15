use std::path::{PathBuf};
use std::io;

pub fn find_git_root() -> io::Result<PathBuf> {
    let mut current = PathBuf::from(".");
    
    loop {
        let git_dir = current.join(".git");
        
        if git_dir.exists() {
            return Ok(current);
        }
        
        if !current.pop() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No git repository found",
            ));
        }
    }
}
