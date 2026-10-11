"""The advisory AI helper: metadata suggestions and plain-language explanations.

Imported by the registry only. core and verifier never import it.
"""

from .explain import Explanation, explain_result
from .extract import suggest_metadata

__all__ = ["Explanation", "explain_result", "suggest_metadata"]
