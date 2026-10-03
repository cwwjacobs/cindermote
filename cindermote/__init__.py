"""Source-checkout package bridge for Cindermote's flat repository layout.

The historical modules import ``cindermote.<component>`` while the repository
stores those components at its root. Extending the package search path keeps
those imports stable without duplicating or symlinking source trees.
"""

from pathlib import Path


__path__ = [str(Path(__file__).resolve().parent.parent)]


# Single source of truth for the version shown by the CLI. ".dev0" marks an
# unreleased tree; the release process drops it when a tag is cut.
__version__ = "1.0.1.dev0"
