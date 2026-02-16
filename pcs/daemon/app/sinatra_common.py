from typing import Optional, Protocol, Union

from tornado.web import _HeaderTypes

from pcs.daemon import ruby_pcsd


# https://mypy.readthedocs.io/en/latest/more_types.html#mixin-classes
class RequestHandlerLike(Protocol):
    def set_header(self, name: str, value: _HeaderTypes) -> None: ...

    def set_default_headers(self) -> None: ...

    def set_status(
        self, status_code: int, reason: Optional[str] = None
    ) -> None: ...

    def write(self, chunk: Union[str, bytes, dict]) -> None: ...


class SinatraMixin:
    """
    Sinatra is base class for handlers which calls the Sinatra via wrapper.
    It accept ruby wrapper during initialization. It also provides method for
    transformation result from sinatra to http response.
    """

    __ruby_pcsd_wrapper: ruby_pcsd.Wrapper

    def initialize_sinatra(self, ruby_pcsd_wrapper: ruby_pcsd.Wrapper) -> None:
        self.__ruby_pcsd_wrapper = ruby_pcsd_wrapper

    def send_sinatra_result(
        self: RequestHandlerLike, result: ruby_pcsd.SinatraResult
    ) -> None:
        for name, value in result.headers.items():
            self.set_header(name, value)
        # make sure that security related headers, which need to be present in
        # all responses, are not overridden by sinatra
        self.set_default_headers()
        self.set_status(result.status)
        self.write(result.body)

    @property
    def ruby_pcsd_wrapper(self) -> ruby_pcsd.Wrapper:
        return self.__ruby_pcsd_wrapper
