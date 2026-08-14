# /// script
# requires-python = ">=3.10"
# dependencies = ["torch>=2.5", "transformers>=4.53", "numpy"]
# ///
"""Stable profile-driven entry point for Bifrost's embedding sidecar."""

from voyage_sidecar import main


if __name__ == "__main__":
    main()
