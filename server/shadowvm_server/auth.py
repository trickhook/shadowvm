from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Header, HTTPException, Request, status
from sqlalchemy import select

from .db import Account, get_sessionmaker

_hasher = PasswordHasher()


def hash_token(token: str) -> str:
    """Produce an argon2id hash of a plaintext bearer token."""
    return _hasher.hash(token)


def verify_token(hashed: str, token: str) -> bool:
    """Check a bearer token against an argon2id hash."""
    try:
        return _hasher.verify(hashed, token)
    except (VerifyMismatchError, Exception):
        return False


class SlidingWindow:
    """In-memory sliding window rate limiter keyed by account+bucket."""
    def __init__(self):
        self._events: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_s: float) -> bool:
        now = time.monotonic()
        dq = self._events[key]
        while dq and (now - dq[0]) > window_s:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

    def snapshot(self) -> dict:
        return {k: list(v) for k, v in self._events.items()}

    def reset(self) -> None:
        self._events.clear()


_rate = SlidingWindow()


def rate_limiter() -> SlidingWindow:
    """Access the shared rate limiter instance."""
    return _rate


async def require_account(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Account:
    """Resolve the account from a Bearer token header or raise 401."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer")
    token = authorization.split(" ", 1)[1].strip()
    sm = get_sessionmaker()
    async with sm() as sess:
        rows = (await sess.execute(select(Account).where(Account.disabled == False))).scalars().all()
    for acc in rows:
        if verify_token(acc.api_token_hash, token):
            request.state.account = acc
            return acc
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")


def check_rate(account_id: str, bucket: str, limit_per_hour: int) -> None:
    """Enforce the per-account sliding window; raise 429 when exceeded."""
    if not _rate.allow(f"{account_id}:{bucket}", limit_per_hour, 3600.0):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"rate limit exceeded for {bucket}")
