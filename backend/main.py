from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from backend.utils.url_validator import validate_url
from backend.security.dns_checker import check_dns
from backend.security.ssl_checker import check_ssl
from backend.security.url_security import check_url_security

app = FastAPI()


class URLRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def home():
    return {"message": "Phishing URL Risk Detector API is running!"}


@app.post("/api/v1/scan")
def scan_url(request: URLRequest):
    is_valid = validate_url(str(request.url))

    domain = request.url.host
    dns_result = check_dns(domain)
    ssl_result = check_ssl(domain)
    url_security_result = check_url_security(str(request.url))

    return {
        "url": str(request.url),
        "valid": is_valid,
        "dns": dns_result,
        "ssl": ssl_result,
        "url_security": url_security_result,
        "message": "URL received successfully"
    }

