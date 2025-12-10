# To pozwala na krótszy import w main.py:
# Zamiast: from modules.sql_injector import sql_scanner
# Będziesz mógł pisać: from modules import sql_scanner

from .sql_injector import sql_scanner
# from .xss_scanner import xss_scanner
