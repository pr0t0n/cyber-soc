"""Tipos de coluna que precisam se comportar diferente em Postgres (produção,
com a extensão pgvector) e SQLite (testes, sem pgvector disponível)."""
from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator


class FlexibleVector(TypeDecorator):
    """`vector(n)` real em Postgres; lista JSON de floats em SQLite (só para
    os testes rodarem sem pgvector — busca por similaridade real precisa de
    Postgres, ver app/services/rag.py). `comparator_factory` delegado ao do
    pgvector para que `.cosine_distance()` continue disponível na expressão
    Python (SQLAlchemy resolve o comparator pelo tipo declarado, não pelo
    dialect em uso — só o DDL/binding muda por dialect)."""

    impl = JSON
    cache_ok = True
    comparator_factory = Vector.comparator_factory

    def __init__(self, dimensions: int):
        super().__init__()
        self.dimensions = dimensions

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(Vector(self.dimensions))
        return dialect.type_descriptor(JSON())
