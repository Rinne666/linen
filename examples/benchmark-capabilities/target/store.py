from dataclasses import dataclass, field
from threading import Lock


@dataclass
class Principal:
    user_id: str
    tenant_id: str


@dataclass
class Document:
    owner_id: str
    tenant_id: str
    body: str


@dataclass
class Store:
    documents: dict[str, Document]
    catalog: dict[str, int]

    def document(self, identifier: str) -> Document:
        return self.documents[identifier]


@dataclass
class Account:
    balance: int
    lock: object = field(default_factory=Lock)
