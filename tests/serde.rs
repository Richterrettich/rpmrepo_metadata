use std::{error::Error, io::BufReader};

use rpm::{Dependency, FileOptions};
use rpmrepo_metadata::{utils, Package};

#[test]
fn test_json_deserialization() -> Result<(), Box<dyn Error>> {
    let path = "./tests/assets/package.json";
    let f = std::fs::File::open(path)?;
    let reader = BufReader::new(f);
    let _: Package = serde_json::from_reader(reader)?;
    Ok(())
}
