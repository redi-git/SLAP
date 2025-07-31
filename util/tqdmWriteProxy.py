from tqdm import tqdm
from typing import TextIO, cast

class tqdmWriteProxy:
    def write(self, message: str):
        tqdm.write(message, end="")

    @classmethod
    def get(cls) -> TextIO:
        return cast(TextIO, cls())