use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOpenMode, CatalogOptions, SemanticPackCatalog,
};
use brokk_bifrost_semantic_packs::release_bundle::{
    BundleInput, generate_release_bundle, install_release_bundle, verify_release_bundle,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage().into());
    };
    let Some(output_root) = arguments.next().map(PathBuf::from) else {
        return Err(usage().into());
    };
    match command.as_str() {
        "generate" => {
            let remaining = arguments.map(PathBuf::from).collect::<Vec<_>>();
            if remaining.is_empty() || remaining.len() % 2 != 0 {
                return Err(usage().into());
            }
            let inputs = remaining
                .chunks_exact(2)
                .map(|pair| BundleInput {
                    spec_path: pair[0].clone(),
                    artifact_path: pair[1].clone(),
                })
                .collect::<Vec<_>>();
            let index = generate_release_bundle(&output_root, &inputs)?;
            println!(
                "generated {} pinned semantic packs in {}",
                index.packs.len(),
                output_root.display()
            );
        }
        "verify" if arguments.next().is_none() => {
            let index = verify_release_bundle(Path::new(&output_root))?;
            println!(
                "verified {} pinned semantic packs in {}",
                index.packs.len(),
                output_root.display()
            );
        }
        "install" => {
            let Some(catalog_root) = arguments.next().map(PathBuf::from) else {
                return Err(usage().into());
            };
            if arguments.next().is_some() {
                return Err(usage().into());
            }
            let catalog = SemanticPackCatalog::open(
                &catalog_root,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )?;
            let installed = install_release_bundle(&output_root, &catalog)?;
            println!(
                "installed {} pinned semantic packs from {} into {}",
                installed.len(),
                output_root.display(),
                catalog_root.display()
            );
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage:\n  bifrost-semantic-pack generate OUTPUT SPEC ARTIFACT [SPEC ARTIFACT ...]\n  bifrost-semantic-pack verify OUTPUT\n  bifrost-semantic-pack install BUNDLE CATALOG"
}
