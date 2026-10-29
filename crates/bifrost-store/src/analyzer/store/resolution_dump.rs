//! Test-support rendering of every prepared resolution family before writing.

use super::*;
use std::io::Write;

impl PreparedResolutionBundle {
    /// Dump the complete producer rows, including path-body precedence at $[8].
    ///
    /// The caller selects and lowers one file at a time. Shared slots and their
    /// digest tables are both retained, so this records all identity registrations
    /// without needing a database or storing expected digests in the repository.
    #[doc(hidden)]
    pub fn write_prepared_rows(&self, output: &mut impl Write) -> std::io::Result<()> {
        writeln!(output, "complete_content_digest {:?}", self.interior_digest)?;
        for (spec, rows) in PreparedResolutionBundleRows::family_specs()
            .iter()
            .zip(self.rows.families())
        {
            writeln!(output, "{} {rows:?}", spec.table)?;
        }
        // Debug retains all columns and shared-name digest registrations.
        writeln!(output, "paths {:?}", self.path_rows)?;
        let shared_ids = (1..=self.path_rows.shared.len())
            .map(|id| i64::try_from(id).expect("file shared count fits i64"))
            .collect::<Vec<_>>();
        for row in &self.path_rows.rows {
            let body = resolution_rows::render_path_body(&row.body, &shared_ids);
            let value: serde_json::Value =
                serde_json::from_str(&body).expect("prepared path body is JSON");
            writeln!(
                output,
                "path {} body {body} precedence {}",
                row.path, value[8]
            )?;
        }
        writeln!(output, "sites {:?}", self.site_rows)?;
        writeln!(output, "typed {:?}", self.typed_fact_rows)?;
        writeln!(output, "recipes {:?}", self.recipe_rows)?;
        writeln!(output, "gaps {:?}", self.gap_rows)?;
        writeln!(output, "shared {:?}", self.shared_name_digests)?;
        Ok(())
    }
}
