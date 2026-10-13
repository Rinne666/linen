"""Server-owned oracle catalog configured at startup, outside worker inputs."""

from pathlib import Path

from linen.contracts.oracle import OracleCatalog, OracleDefinition

_catalog_path: Path | None = None


def configure_oracle_catalog(path: Path | None) -> None:
    global _catalog_path
    if path is not None:
        OracleCatalog.model_validate_json(path.read_bytes())
    _catalog_path = path.resolve() if path is not None else None


def approved_oracle(project_id: str, candidate_id: str, source_generation: int, plan_revision: int) -> OracleDefinition:
    if _catalog_path is None:
        raise ValueError("no trusted independent-oracle catalog configured on the server")
    catalog = OracleCatalog.model_validate_json(_catalog_path.read_bytes())
    return catalog.bound_definition(project_id, candidate_id, source_generation, plan_revision)
