import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("user_logger")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("logs/app.log", maxBytes=5000000, backupCount=3)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)