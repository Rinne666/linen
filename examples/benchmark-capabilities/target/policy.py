from .store import Document, Principal


def may_read(principal: Principal, document: Document) -> bool:
    return principal.user_id == document.owner_id and principal.tenant_id == document.tenant_id
