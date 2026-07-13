import os
from dotenv import load_dotenv

load_dotenv()

MISP_CONFIG = {
    'url': 'http://localhost',
    'key': 'your-misp-api-key-here',  # Will be generated later
    'ssl': False,
    'debug': True,
    'proxies': None,
    'cert': None,
    'auth': None,
    'tool': 'LangChain-MISP-Integration'
}

# OpenAI API configuration (optional - for advanced AI features)
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
