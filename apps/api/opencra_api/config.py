from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    supabase_url: str = "http://127.0.0.1:54321"
    supabase_jwt_secret: str = "dev-secret-change-me"
    supabase_anon_key: str = ""
    database_url: str = "sqlite+pysqlite:///./opencra.db"
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_pro_plus: str = ""
    public_app_url: str = "http://localhost:5173"
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    dev_auth: bool = True


settings = Settings()
