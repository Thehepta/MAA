import logging
import sys

console_logger = logging.getLogger("unique_console")
console_logger.handlers.clear()
console_logger.addHandler(logging.StreamHandler(sys.stdout))
console_logger.setLevel(logging.DEBUG)
console_logger.propagate = False