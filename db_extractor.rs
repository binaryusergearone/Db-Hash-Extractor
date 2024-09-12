use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;
use regex::Regex;

struct MySQLCredentialExtractor {
    input_file: String,
    output_file: String,
}

impl MySQLCredentialExtractor {
    fn new(input_file: String, output_file: String) -> Self {
        Self { input_file, output_file }
    }

    fn validate_files(&self) {
        if !Path::new(&self.input_file).exists() {
            eprintln!("Error: The file '{}' does not exist.", self.input_file);
            std::process::exit(1);
        }
    }

    fn read_db_file(&self) -> Vec<String> {
        let file = File::open(&self.input_file).unwrap();
        let reader = io::BufReader::new(file);
        reader.lines().map(|l| l.unwrap()).collect()
    }

    fn decrypt_or_crack(&self, data: Vec<String>) -> Vec<(String, String)> {
        data.iter().filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let username = parts[0].to_string();
                let password = parts[1].to_string();
                let decrypted_password = self.detect_hash_type(&password);
                Some((username, decrypted_password))
            } else {
                None
            }
        }).collect()
    }

    fn detect_hash_type(&self, password: &str) -> String {
        if self.is_md5_hash(password) {
            format!("[MD5 Hash: {}]", password)
        } else if self.is_sha1_hash(password) {
            format!("[SHA-1 Hash: {}]", password)
        } else if self.is_sha256_hash(password) {
            format!("[SHA-256 Hash: {}]", password)
        } else if self.is_sha512_hash(password) {
            format!("[SHA-512 Hash: {}]", password)
        } else if self.is_bcrypt_hash(password) {
            format!("[bcrypt Hash: {}]", password)
        } else {
            password.to_string()
        }
    }

    fn is_md5_hash(&self, password: &str) -> bool {
        password.len() == 32 && password.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_sha1_hash(&self, password: &str) -> bool {
        password.len() == 40 && password.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_sha256_hash(&self, password: &str) -> bool {
        password.len() == 64 && password.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_sha512_hash(&self, password: &str) -> bool {
        password.len() == 128 && password.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_bcrypt_hash(&self, password: &str) -> bool {
        let bcrypt_regex = Regex::new(r"^\$2[ayb]\$.{56}$").unwrap();
        bcrypt_regex.is_match(password)
    }

    fn save_to_file(&self, credentials: Vec<(String, String)>) {
        let mut file = File::create(&self.output_file).unwrap();
        for (username, password) in credentials {
            writeln!(file, "Username: {}, Password: {}", username, password).unwrap();
        }
    }

    fn run(&self) {
        self.validate_files();
        let data = self.read_db_file();
        let credentials = self.decrypt_or_crack(data);
        self.save_to_file(credentials);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: cargo run <input_db_file> <output_file>");
        std::process::exit(1);
    }

    let extractor = MySQLCredentialExtractor::new(args[1].clone(), args[2].clone());
    extractor.run();
          }
