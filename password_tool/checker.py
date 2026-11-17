"""Password strength evaluation using zxcvbn and additional local checks."""

from zxcvbn import zxcvbn

COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567",
    "password",
    "password1",
    "qwerty",
    "abc123",
    "111111",
    "123123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "master",
    "sunshine",
}


def check_strength(password: str) -> dict:
    """Return a zxcvbn score, crack-time estimate, suggestions, and strength flag."""
    result = zxcvbn(password)
    feedback = []

    zxcvbn_feedback = result.get("feedback", {})
    if zxcvbn_feedback.get("warning"):
        feedback.append(zxcvbn_feedback["warning"])
    feedback.extend(zxcvbn_feedback.get("suggestions", []))

    if len(password) < 12:
        feedback.append("Use at least 12 characters.")
    if not any(char.isupper() for char in password):
        feedback.append("Add an uppercase letter.")
    if not any(char.islower() for char in password):
        feedback.append("Add a lowercase letter.")
    if not any(char.isdigit() for char in password):
        feedback.append("Add a digit.")
    if not any(not char.isalnum() for char in password):
        feedback.append("Add a symbol.")
    if password.casefold() in COMMON_PASSWORDS:
        feedback.append("Avoid common passwords.")

    # Keep suggestions specific while preserving their original order.
    feedback = list(dict.fromkeys(feedback))
    crack_time = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]

    return {
        "score": result["score"],
        "crack_time_display": crack_time,
        "feedback": feedback,
        "is_strong": result["score"] >= 3,
    }
