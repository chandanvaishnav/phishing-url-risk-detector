import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from backend.database import init_db, get_connection
from backend.utils.url_validator import validate_url
from backend.security.dns_checker import check_dns
from backend.security.ssl_checker import check_ssl
from backend.security.url_security import check_url_security


app = FastAPI(
    title="Phishing URL Risk Detector API",
    description="Backend API for detecting suspicious and phishing URLs.",
    version="1.0.0"
)


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

    try:
        # Convert URL to string
        url = str(request.url)

        # Validate URL
        is_valid = validate_url(url)

        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail="Invalid URL"
            )

        # Get domain
        domain = request.url.host

        if not domain:
            raise HTTPException(
                status_code=400,
                detail="Could not extract domain from URL"
            )

        # Security checks
        dns_result = check_dns(domain)
        ssl_result = check_ssl(domain)
        url_security_result = check_url_security(url)

        # Create scan result
        result = {
            "url": url,
            "valid": is_valid,
            "dns": dns_result,
            "ssl": ssl_result,
            "url_security": url_security_result,
            "message": "URL scanned successfully"
        }

        # Save scan result to database
        connection = get_connection()

        connection.execute(
            """
            INSERT INTO scan_history (url, result_json)
            VALUES (?, ?)
            """,
            (
                url,
                json.dumps(result)
            )
        )

        connection.commit()
        connection.close()

        return result

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while scanning the URL"
        )


@app.get("/api/v1/history")
def get_history():

    try:
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

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve scan history"
        )