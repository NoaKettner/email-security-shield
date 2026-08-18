from fastapi import FastAPI

from parser import parse_email
from identity_analyzer import analyze_sender
from link_analyzer import analyze_links
from authentication_analyzer import analyze_authentication
from content_analyzer import analyze_content
from attachment_analyzer import analyze_attachments
from structure_analyzer import analyze_structure
from scoring import calculate_risk


app = FastAPI()


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/api/v1/analyze")
def analyze_email(email_json: dict):
    email = parse_email(email_json)

    signals = (
        analyze_sender(email)
        + analyze_links(email)
        + analyze_authentication(email)
        + analyze_content(email)
        + analyze_attachments(email)
        + analyze_structure(email)
    )

    return calculate_risk(signals)
