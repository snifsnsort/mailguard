# base_provider.py
#
# Base interface for all external intelligence providers.
# Each provider in this module should inherit from IntelProvider,
# override `name`, and implement the lookup() method.

class IntelProvider:
    """
    Abstract base class for external intel providers.
    """
    name = "base"  # Subclasses must override this with a unique provider name

    def lookup(self, value: str) -> dict:
        """
        Perform a lookup for the given value (domain, IP, etc).
        Returns a dict of enrichment data.
        Must be implemented by each provider.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement lookup()"
        )
