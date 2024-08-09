from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy.future import select
from embeddings import EmbeddingModel
from models import Base, CWE, CVE
import numpy as np

class Database:
    def __init__(self, database_uri, embedding_model: EmbeddingModel):
        self.engine = create_async_engine(database_uri, echo=True)
        self.create_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        self.embedding_model = embedding_model

    async def init_db(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def insert_cwe(self, cwe_id, cwe_name):
        async with self.create_session() as session:
            cwe = CWE(cwe_id=cwe_id, cwe_name=cwe_name)
            session.add(cwe)
            await session.commit()

    async def insert_cve(self, cwe_id, cve_id, description):
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_id=cwe_id)
            )
            cwe = result.scalar_one_or_none()
            if cwe is None:
                await self.insert_cwe(cwe_id)
                result = await session.execute(
                    select(CWE).filter_by(cwe_id=cwe_id)
                )
                cwe = result.scalar_one_or_none()
            embedding_vector = self.embedding_model.create_embedding(description)
            cve = CVE(
                cve_id=cve_id,
                cwe_id=cwe_id,
                description=description,
                embedding=embedding_vector.tolist()
            )
            session.add(cve)
            await session.commit()

    '''
    async def insert_cves_batch(self, cwe_name, cves):
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_name=cwe_name)
            )
            cwe = result.scalar_one_or_none()
            if cwe is None:
                await self.insert_cwe(cwe_name)
                result = await session.execute(
                    select(CWE).filter_by(cwe_name=cwe_name)
                )
                cwe = result.scalar_one_or_none()

            cve_objects = []
            for cve_name, description in cves:
                embedding_vector = self.embedding_model.create_embedding(description)
                cve = CVE(
                    cwe_id=cwe.cwe_id,
                    cve_name=cve_name,
                    description=description,
                    embedding=embedding_vector.tolist()
                )
                cve_objects.append(cve)

            session.add_all(cve_objects)
            await session.commit()
    '''

    '''
    async def insert_cwes_batch(self, cwes):
        async with self.create_session() as session:
            cwe_objects = [CWE(cwe_name=cwe_name) for cwe_name in cwes]
            session.add_all(cwe_objects)
            await session.commit()
    '''

    async def update_cwe_name(self, old_cwe_name, new_cwe_name):
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_name=old_cwe_name)
            )
            cwe = result.scalar_one_or_none()
            if cwe:
                cwe.cwe_name = new_cwe_name
                await session.commit()

    async def update_cve_description(self, cwe_name, cve_name, new_description):
        embedding_vector = self.embedding_model.create_embedding(new_description)
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_name=cwe_name)
            )
            cwe = result.scalar_one_or_none()
            if cwe:
                result = await session.execute(
                    select(CVE).filter_by(cwe_id=cwe.cwe_id, cve_name=cve_name)
                )
                cve = result.scalar_one_or_none()
                if cve:
                    cve.description = new_description
                    cve.embedding = embedding_vector.tolist()
                    await session.commit()

    async def delete_cwe(self, cwe_name):
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_name=cwe_name)
            )
            cwe = result.scalar_one_or_none()
            if cwe:
                session.delete(cwe)
                await session.commit()

    async def delete_cve(self, cwe_name, cve_name):
        async with self.create_session() as session:
            result = await session.execute(
                select(CWE).filter_by(cwe_name=cwe_name)
            )
            cwe = result.scalar_one_or_none()
            if cwe:
                result = await session.execute(
                    select(CVE).filter_by(cwe_id=cwe.cwe_id, cve_name=cve_name)
                )
                cve = result.scalar_one_or_none()
                if cve:
                    session.delete(cve)
                    await session.commit()

    async def search_cves_by_description(self, query, top_k=5):
        embedding_vector = self.embedding_model.create_embedding(query) if isinstance(query, str) else query
        if isinstance(embedding_vector, np.ndarray):
            embedding_vector = embedding_vector.tolist()
        elif not isinstance(embedding_vector, list):
            raise ValueError("Invalid query type, expected str, list or numpy array")
        async with self.create_session() as session:
            result = await session.execute(
                select(CVE, (1 - CVE.embedding.cosine_distance(embedding_vector)).label('similarity'))
                .options(joinedload(CVE.CWE))
                .order_by(CVE.embedding.cosine_distance(embedding_vector))
                .limit(top_k)
            )
            return result.all()

    async def search_cves_by_constraint(self, cwe_name, cve_name, top_k=5):
        async with self.create_session() as session:
            # Fetch the embedding of the specified cve and CWE
            result = await session.execute(
                select(CVE)
                .join(CWE)
                .filter(CWE.cwe_name == cwe_name, CVE.cve_name == cve_name)
            )
            cve = result.all().pop()
            try:
                embedding_vector = cve[0].embedding
            except Exception as e:
                raise ValueError(f"CVE '{cve_name}' not found in CWE '{cwe_name}'")
            if isinstance(embedding_vector, np.ndarray):
                embedding_vector = embedding_vector.tolist()
            elif not isinstance(embedding_vector, list):
                raise ValueError("Invalid query type, expected str, list or numpy array")
            result = await session.execute(
                select(CVE, (1 - CVE.embedding.cosine_distance(embedding_vector)).label('similarity'))
                .options(joinedload(CVE.CWE))
                .filter(CVE.cve_name != cve_name)
                .order_by(CVE.embedding.cosine_distance(embedding_vector))
                .limit(top_k)
            )
            return result.all()
        
    async def close(self):
        await self.engine.dispose()
