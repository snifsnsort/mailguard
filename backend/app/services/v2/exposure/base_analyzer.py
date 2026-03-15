# base_analyzer.py
#
# Base class for all exposure analysis modules.
# routing_analysis, connector_analysis, mx_analysis, and mailflow_graph
# should all inherit from ExposureAnalyzer.

class ExposureAnalyzer:
    """
    Base class for exposure analysis modules.
    """

    def analyze(self, request) -> dict:
        """
        Run analysis against the given scan request.
        Must be implemented by each subclass.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement analyze()"
        )
