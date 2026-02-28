mod types;

pub use types::*;

use std::fs;
use std::path::Path;

use anyhow::Context as _;
use anyhow::Result;

pub fn load_from(path: impl AsRef<Path>) -> Result<Config> {
    let text =
        fs::read_to_string(&path).with_context(|| format!("read config: {:?}", path.as_ref()))?;
    let cfg: Config = toml::from_str(&text).context("failed to parse config file")?;
    Ok(cfg)
}
