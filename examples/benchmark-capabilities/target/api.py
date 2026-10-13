from collections.abc import Callable

from . import policy
from .store import Account, Principal, Store


def case_001(principal: Principal, document_id: str, store: Store) -> str:
    document = store.document(document_id)
    return document.body


def case_002(principal: Principal, document_id: str, store: Store) -> str:
    document = store.document(document_id)
    if not policy.may_read(principal, document):
        raise PermissionError("Document access denied")
    return document.body


def case_003(principal: Principal, document_id: str, store: Store) -> str:
    document = store.document(document_id)
    if principal.user_id != document.owner_id:
        raise PermissionError("Document access denied")
    return document.body


def case_004(principal: Principal, document_id: str, store: Store) -> str:
    document = store.document(document_id)
    if not policy.may_read(principal, document):
        raise PermissionError("Document access denied")
    return document.body


def case_005(principal: Principal, product_id: str, paid_amount: int, store: Store) -> dict:
    if paid_amount <= 0:
        raise ValueError("Payment must be positive")
    return {"user_id": principal.user_id, "product_id": product_id,
            "charged": paid_amount, "fulfilled": True}


def case_006(principal: Principal, product_id: str, paid_amount: int, store: Store) -> dict:
    price = store.catalog[product_id]
    if paid_amount != price:
        raise PermissionError("Payment does not match the catalog price")
    return {"user_id": principal.user_id, "product_id": product_id,
            "charged": price, "fulfilled": True}


def case_007(account: Account, amount: int, authorize: Callable[[int], bool]) -> bool:
    if amount <= 0:
        raise ValueError("Withdrawal must be positive")
    if account.balance < amount:
        return False
    if not authorize(amount):
        return False
    account.balance -= amount
    return True


def case_008(account: Account, amount: int, authorize: Callable[[int], bool]) -> bool:
    if amount <= 0:
        raise ValueError("Withdrawal must be positive")
    with account.lock:
        if account.balance < amount:
            return False
        if not authorize(amount):
            return False
        account.balance -= amount
        return True
