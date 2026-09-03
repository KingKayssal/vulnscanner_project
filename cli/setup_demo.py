"""
Demo setup: creates an Organization + AuthorizedTarget so the scanner's
authorization gate allows scanning our local test app.

In real usage this is done through the API/admin UI with an actual
signed authorization document, not a script.
"""
import datetime
from db.session import init_db, get_session
from db.models import Organization, AuthorizedTarget

if __name__ == "__main__":
    init_db()
    session = get_session()

    existing = session.query(Organization).filter_by(name="Demo Org").first()
    if existing:
        print("Demo org already exists:", existing.id)
    else:
        org = Organization(name="Demo Org")
        session.add(org)
        session.flush()

        target = AuthorizedTarget(
            organization_id=org.id,
            domain="127.0.0.1",
            authorized_by="internal security team (demo authorization)",
            authorization_doc_url="https://internal-wiki.example/authz/demo-scan-2026",
            valid_from=datetime.date.today(),
            valid_until=datetime.date(2030, 1, 1),
            excluded_paths=[],
        )
        session.add(target)
        session.commit()
        print("Created org:", org.id, "target:", target.id)
