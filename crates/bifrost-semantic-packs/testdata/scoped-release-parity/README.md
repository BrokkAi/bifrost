# Scoped release parity golden

This expected output belongs only to the release-bundle test in
`src/release_bundle.rs`. The test creates its JDK source archive with the local
`jdk_generated_bundle_input` fixture builder, and uses the small npm declaration
and Ruby RBS examples already exercised by this module's producer tests. All
artifacts are generated in a temporary directory; no product pack is authored
or registered by this fixture.
