# Bifrost npm packaging

This directory builds the public `@brokkai/bifrost` npm package and its
platform packages from a published Bifrost GitHub release.

Do not build native files in this directory. The package script verifies each
GitHub release archive with its SHA-256 sidecar. It then puts that released
binary in the applicable platform package.

The publish script publishes all platform packages first. It publishes the
root wrapper only after all platform versions are available from npm. The
script skips versions that already exist. Thus, you can run it again after a
partial publication.

`@brokkai/bifrost` is the native CLI package. It is separate from the existing
`@brokk/bifrost-agent` Pi extension.
