# Callable service contract

This package exposes eight entry points in `api.py`. Source, policy and state
are entirely local. The caller supplies a trusted authenticated `Principal`, a
server-owned `Store` or `Account`, and untrusted object identifiers and amounts.

User identifiers are tenant-local: identity is the pair `(tenant_id, user_id)`.
Documents are private to that identity. Successful document reads return the
body, and denied reads raise `PermissionError`.

A successful order grants fulfillment. Catalog prices are server-owned and
there are no coupons, discounts, partial payments or administrator exceptions.
Payment below the catalog price must not grant fulfillment.

Withdrawal requests can execute concurrently. The authorization callback is a
trusted payment integration that can block while an external operation finishes;
it does not update the account balance. Successful withdrawals must not exceed
the starting balance in aggregate. Amounts and prices use integer minor units.
