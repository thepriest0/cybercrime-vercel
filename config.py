import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://cybercrime_user:iVk5T18JBYdeAmHLvLn32nWMnr4FZlBq@dpg-cpql41aj1k6c73bic3b0-a/cybercrime')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'your_secret_key'
