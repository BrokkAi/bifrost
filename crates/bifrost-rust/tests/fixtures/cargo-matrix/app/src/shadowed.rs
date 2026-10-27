// Test-only negative import: a local type binding shadows the extern name.
use crate::outer::inner::Item as dep_alias;
use crate::branch::leaf::Leaf as Another;
use dep_alias::outer::inner::Item as Incorrect;
