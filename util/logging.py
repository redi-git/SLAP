import colorlog

handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s %(asctime)s%(reset)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
    )
)

logger = colorlog.getLogger("main")
logger.addHandler(handler)
logger.setLevel(colorlog.DEBUG)
