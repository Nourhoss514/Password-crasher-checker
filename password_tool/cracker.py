"""Hashing utilities for a limited, self-generated hash learning demo."""

import hashlib
import hmac

import bcrypt

SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}


def hash_password(password: str, algo: str) -> str:
    """Hash a password with a demo digest or salted bcrypt."""
    if isinstance(algo, str) and algo.lower() == "bcrypt":
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")

    try:
        hash_function = SUPPORTED_ALGORITHMS[algo.lower()]
    except (AttributeError, KeyError) as error:
        raise ValueError("Algorithm must be md5, sha1, sha256, or bcrypt.") from error
    return hash_function(password.encode("utf-8")).hexdigest()


def verify_candidate(candidate: str, generated_hash: str, algo: str) -> bool:
    """Check one candidate against a hash generated in the current app session."""
    if isinstance(algo, str) and algo.lower() == "bcrypt":
        return bcrypt.checkpw(candidate.encode("utf-8"), generated_hash.encode("ascii"))

    candidate_hash = hash_password(candidate, algo)
    return hmac.compare_digest(candidate_hash, generated_hash.lower())
