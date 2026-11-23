from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from Database.database import get_db
from Database.tables import Domain
from fastapi.exceptions import HTTPException
from models.url_schema import URLRequest, URLResponse
from services.pishing_url import analyze_url
from models.user_Schema import get_current_user
from services.email import send_email

domain_router = APIRouter(prefix="/pishing-url", tags=["Pishing Url Tester"])

def _send_phishing_email(to_email: str, url: str, reason: str):
    """
    Helper function to send phishing alert emails.
    This function is intended to be run in the background.
    """
    send_email(
        to_email=to_email,
        subject="⚠️ Phishing Alert",
        body=f"""
        The URL you checked is identified as PHISHING.

        URL: {url}

        Reason:
        {reason}

        Please avoid visiting this site.
        """
    )

@domain_router.post("/check", response_model=URLResponse)
def check_domain(
    request: URLRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    background_tasks: BackgroundTasks = Depends()
):
    try:
        existing = db.query(Domain).filter(Domain.url == request.url).first()
        if existing:
            return {
                "url": existing.url,
                "is_phishing": bool(existing.is_phishing),
                "reason": existing.reason
            }

        result = analyze_url(request.url)
        new_domain = Domain(
            url=result["url"],
            reason=result["reason"],
            is_phishing=bool(result.get("is_phishing", False))
        )
        db.add(new_domain)
        db.commit()
        db.refresh(new_domain)

        if result.get("is_phishing") and not existing:
            background_tasks.add_task(
                _send_phishing_email,
                to_email=current_user.email,
                url=result["url"],
                reason=result["reason"]
            )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))