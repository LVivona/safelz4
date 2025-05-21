#![warn(missing_docs)]
#![doc(html_logo_url = "")]
#![doc = include_str!("../README.md")]
use pyo3::prelude::*;

mod block;
mod error;
mod frame;

use block::register_block_module;
use error::register_error_module;
use frame::register_frame_module;

/// A Python module implemented in Rust.
#[pymodule]
fn _safelz4_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // basic block module for more control in context to block
    register_block_module(m)?;

    // simple Error module for LZ4Exception throwing
    register_error_module(m)?;

    // register frame module habdling decompress, and compress files.
    register_frame_module(m)?;

    // Add version and description as module-level constants
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__doc__", env!("CARGO_PKG_DESCRIPTION"))?;
    Ok(())
}
