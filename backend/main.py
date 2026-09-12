import json

from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

from backend.database import init_db, get_connection
from backend.utils.url_validator import validate_url
from backend.security.dns_checker import check_dns
from backend.security.ssl_checker import check_ssl
from backend.security.url_security import check_url_security


app = FastAPI()

# Initialize database when the application starts
init_db()


class URLRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def home():
    return {
        "message": "Phishing URL Risk Detector API is running!"
    }


@app.post("/api/v1/scan")
def scan_url(request: URLRequest):

    # Validate URL
    is_valid = validate_url(str(request.url))

    # Get domain
    domain = request.url.host

    # Security checks
    dns_result = check_dns(domain)
    ssl_result = check_ssl(domain)
    url_security_result = check_url_security(str(request.url))

    # Create scan result
    result = {
        "url": str(request.url),
        "valid": is_valid,
        "dns": dns_result,
        "ssl": ssl_result,
        "url_security": url_security_result,
        "message": "URL received successfully"
    }

    # Save scan result to database
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO scan_history (url, result_json)
        VALUES (?, ?)
        """,
        (
            str(request.url),
            json.dumps(result)
        )
    )

    connection.commit()
    connection.close()

    return result


@app.get("/api/v1/history")
def get_history():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT id, url, classification, risk_score,
               confidence, scan_time
        FROM scan_history
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    history = []

    for row in rows:
        history.append({
            "id": row["id"],
            "url": row["url"],
            "classification": row["classification"],
            "risk_score": row["risk_score"],
            "confidence": row["confidence"],
            "scan_time": row["scan_time"]
        })

    return history