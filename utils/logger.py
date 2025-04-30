import logging
from config import LOGGING

def setup_logger(name, log_file=None):
    """設置統一的日誌處理器"""
    logger = logging.getLogger(name)
    
    if logger.handlers:  # 避免重複添加處理器
        return logger
        
    logger.setLevel(getattr(logging, LOGGING['LOG_LEVEL']))
    formatter = logging.Formatter(LOGGING['LOG_FORMAT'])
    
    # 添加文件處理器
    if log_file and LOGGING['DEBUG_MODE']:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # 添加控制台處理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger 