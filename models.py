from sqlalchemy import Column, Integer, String, Text, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import DeclarativeBase, mapped_column, relationship
from pgvector.sqlalchemy import Vector

class Base(DeclarativeBase):
    pass

class CWE(Base):
    __tablename__ = 'cwe'

    cwe_id = Column(String(255), primary_key=True, nullable=False)
    cwe_name = Column(String(255), unique=True)

    cve = relationship("CVE", back_populates="cwe")

class CVE(Base):
    __tablename__ = 'cve'

    cve_id = Column(String(255), primary_key=True, nullable=False)
    cwe_id = Column(String(255), ForeignKey('cwe.cwe_id'), nullable=False)
    description = Column(Text)
    embedding = mapped_column(Vector(1024))

    cwe = relationship("CWE", back_populates="cve")

    index = Index(
    'embedding_idx',
    embedding,
    postgresql_using='hnsw',
    postgresql_ops={'embedding': 'vector_cosine_ops'}
    )

    __table_args__ = (index,)
