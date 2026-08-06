//! JVM realm support shared by the Java, Scala, and Kotlin analyzers.
//!
//! Java, Scala, and Kotlin compile to one classpath, so they share one
//! dependency universe: the same Maven/Gradle artifacts, the same jar-backed
//! declaration index, and the same build-manifest inputs that invalidate it.
//! Everything in this module is language-neutral by construction; per-language
//! behaviour belongs in `crate::analyzer::{java, scala, kotlin}`.

pub(crate) mod dependency_discovery;
pub(crate) mod external;
pub(crate) mod java_artifact;
pub(crate) mod jdk_artifact;
pub(crate) mod kotlin_artifact;
pub(crate) mod realm_builder;
pub(crate) mod scala_artifact;
