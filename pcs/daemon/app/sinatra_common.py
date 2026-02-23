from pcs.daemon import ruby_pcsd


class SinatraMixin:
    """
    Sinatra is base class for handlers which calls the Sinatra via wrapper.
    It accept ruby wrapper during initialization. It also provides method for
    transformation result from sinatra to http response.
    """

    __ruby_pcsd_wrapper: ruby_pcsd.Wrapper

    def initialize_sinatra(self, ruby_pcsd_wrapper: ruby_pcsd.Wrapper) -> None:
        self.__ruby_pcsd_wrapper = ruby_pcsd_wrapper

    def send_sinatra_result(self, result: ruby_pcsd.SinatraResult) -> None:
        for name, value in result.headers.items():
            self.set_header(name, value)  # type: ignore[attr-defined]
        # make sure that security related headers, which need to be present in
        # all responses, are not overridden by sinatra
        self.set_default_headers()  # type: ignore[attr-defined]
        self.set_status(result.status)  # type: ignore[attr-defined]
        self.write(result.body)  # type: ignore[attr-defined]

    @property
    def ruby_pcsd_wrapper(self) -> ruby_pcsd.Wrapper:
        return self.__ruby_pcsd_wrapper
