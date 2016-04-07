from .server import run_server
from .settings import get_settings
import logging

def main():
    logging.basicConfig(level=logging.WARN)
    
    settings = get_settings()
    return run_server(settings)
    
if __name__ == "__main__":
    exit(main())
