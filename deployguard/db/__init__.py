"""
db/__init__.py — Database package for DeployGuard AI.

Exposes the MongoDB client singleton and the two primary query functions:

    - ``get_blast_radius``  — $graphLookup transitive dependency traversal
    - ``find_similar_incidents`` — Atlas $vectorSearch semantic similarity
"""

from deployguard.db.client import MongoDBClient, get_db_client
from deployguard.db.db_operations import get_blast_radius, find_similar_incidents

__all__ = [
    "MongoDBClient",
    "get_db_client",
    "get_blast_radius",
    "find_similar_incidents",
]

