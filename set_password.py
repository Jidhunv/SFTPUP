"""Set the SFileUp password. Enforces a strong password and stores only a hash."""
import getpass
import re
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

MIN_LEN = 14


def problems(pw: str) -> list[str]:
    out = []
    if len(pw) < MIN_LEN:
        out.append(f"at least {MIN_LEN} characters")
    if not re.search(r"[a-z]", pw):
        out.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        out.append("an uppercase letter")
    if not re.search(r"\d", pw):
        out.append("a digit")
    if not re.search(r"[^\w\s]", pw):
        out.append("a symbol")
    if re.search(r"(.)\1{2,}", pw):
        out.append("no character repeated 3+ times in a row")
    if pw.lower() in {"password1234567", "qwerty12345678"}:
        out.append("not a common password")
    return out


def main():
    pw = getpass.getpass("New password: ")
    bad = problems(pw)
    if bad:
        sys.exit("Password too weak. Needs: " + ", ".join(bad))
    if getpass.getpass("Confirm password: ") != pw:
        sys.exit("Passwords do not match.")
    h = generate_password_hash(pw, method="scrypt")
    (Path(__file__).resolve().parent / "password.hash").write_text(h)
    print("Saved password.hash")


if __name__ == "__main__":
    main()
