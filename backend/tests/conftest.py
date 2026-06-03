"""
Shared pytest fixtures for backend tests.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from pymongo.errors import DuplicateKeyError

from main import app
from auth import get_password_hash, create_access_token


# ── In-memory test "database" ────────────────────────────────────────────────

class _DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class _InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class _UpdateResult:
    def __init__(self, modified_count, upserted_id=None):
        self.modified_count = modified_count
        self.upserted_id = upserted_id


class FakeCursor:
    """Minimal async cursor shim that supports sort/skip/limit chaining."""

    def __init__(self, data):
        self._data = list(data)
        self._index = 0

    def sort(self, key=None, direction=1):
        if key is None:
            return self
        reverse = direction == -1
        self._data.sort(
            key=lambda item: (
                item.get(key) is None,
                item.get(key),
            ),
            reverse=reverse,
        )
        return self

    def limit(self, n):
        self._data = self._data[:n]
        return self

    def skip(self, n):
        self._data = self._data[n:]
        return self

    def batch_size(self, _n):
        return self

    async def to_list(self, length=None):
        if length is not None:
            return self._data[:length]
        return self._data

    def __aiter__(self):
        self._index = 0
        return self

    async def __anext__(self):
        if self._index >= len(self._data):
            raise StopAsyncIteration
        item = self._data[self._index]
        self._index += 1
        return item


def _match_field(doc_val, spec):
    """Match a doc value against a Mongo-style operator spec."""
    import re as _re
    if not isinstance(spec, dict):
        return doc_val == spec
    for op, operand in spec.items():
        if op == "$in":
            if doc_val not in operand:
                return False
        elif op == "$nin":
            if doc_val in operand:
                return False
        elif op == "$gte":
            if doc_val is None or doc_val < operand:
                return False
        elif op == "$gt":
            if doc_val is None or doc_val <= operand:
                return False
        elif op == "$lte":
            if doc_val is None or doc_val > operand:
                return False
        elif op == "$lt":
            if doc_val is None or doc_val >= operand:
                return False
        elif op == "$ne":
            if doc_val == operand:
                return False
        elif op == "$regex":
            flags = 0
            if spec.get("$options", "").find("i") != -1:
                flags |= _re.IGNORECASE
            if doc_val is None or not _re.search(operand, doc_val, flags):
                return False
        elif op == "$options":
            continue  # handled with $regex
    return True


def _match_doc(doc, query):
    """Recursively match a document against a Mongo-style query."""
    for k, v in query.items():
        if k == "$or":
            if not any(_match_doc(doc, sub) for sub in v):
                return False
            continue
        if k == "$and":
            if not all(_match_doc(doc, sub) for sub in v):
                return False
            continue
        if not _match_field(doc.get(k), v):
            return False
    return True


class FakeCollection:
    """Minimal async collection shim for tests."""

    def __init__(self, data=None):
        self._data = list(data or [])

    async def create_index(self, *args, **kwargs):
        return kwargs.get("name")

    async def find_one(self, query, *args, **kwargs):
        for doc in self._data:
            if all(doc.get(k) == v for k, v in query.items() if not isinstance(v, dict)):
                return doc
        return None

    def find(self, query=None, projection=None):
        if not query:
            return FakeCursor(list(self._data))
        results = []
        for doc in self._data:
            if _match_doc(doc, query):
                results.append(doc)
        return FakeCursor(results)

    def aggregate(self, pipeline):
        return FakeCursor([])

    async def insert_one(self, doc):
        if "_id" not in doc:
            from bson import ObjectId
            doc["_id"] = ObjectId()
        elif any(existing.get("_id") == doc["_id"] for existing in self._data):
            raise DuplicateKeyError(f"Duplicate _id: {doc['_id']}")
        self._data.append(doc)
        return _InsertResult(doc["_id"])

    async def replace_one(self, query, replacement, upsert=False):
        for i, doc in enumerate(self._data):
            if all(doc.get(k) == v for k, v in query.items()):
                self._data[i] = replacement
                return
        if upsert:
            self._data.append(replacement)

    async def update_one(self, query, update, upsert=False):
        # Pull $or off the query and evaluate it as a disjunction of the
        # remaining sub-filters (each a plain equality match). Sufficient
        # for the lock-acquisition pattern in services/extensions/manager.py.
        or_clauses = query.pop("$or", None) if isinstance(query, dict) else None

        def _matches(doc):
            base_match = all(doc.get(k) == v for k, v in query.items())
            if not base_match:
                return False
            if or_clauses is None:
                return True
            for clause in or_clauses:
                # Each clause is itself an equality dict, possibly with
                # an {"$exists": False} expression.
                if all(_match_field(doc, k, v) for k, v in clause.items()):
                    return True
            return False

        def _match_field(doc, key, expected):
            if isinstance(expected, dict) and "$exists" in expected:
                exists = key in doc
                return exists is bool(expected["$exists"])
            return doc.get(key) == expected

        for doc in self._data:
            if _matches(doc):
                for op, fields in update.items():
                    if op == "$set":
                        doc.update(fields)
                    elif op == "$inc":
                        for key, value in fields.items():
                            doc[key] = doc.get(key, 0) + value
                    elif op == "$push":
                        for key, value in fields.items():
                            doc.setdefault(key, []).append(value)
                return _UpdateResult(modified_count=1)
        if upsert:
            # Mongo's upsert refuses to insert a duplicate _id when the
            # query carried a literal _id but no doc matched the full
            # filter. Match Mongo here: in that case it's a no-op for
            # both modified_count and upserted_id (the caller treats
            # it as "couldn't acquire").
            if "_id" in query and any(
                d.get("_id") == query["_id"] for d in self._data
            ):
                return _UpdateResult(modified_count=0, upserted_id=None)
            new_doc = {k: v for k, v in query.items() if not isinstance(v, dict) or "$exists" not in v}
            for op, fields in update.items():
                if op == "$set":
                    new_doc.update(fields)
                elif op == "$inc":
                    for key, value in fields.items():
                        new_doc[key] = new_doc.get(key, 0) + value
                elif op == "$push":
                    for key, value in fields.items():
                        new_doc[key] = [value]
            self._data.append(new_doc)
            return _UpdateResult(modified_count=0, upserted_id=new_doc.get("_id"))
        return _UpdateResult(modified_count=0)

    async def update_many(self, query, update):
        modified = 0
        for doc in self._data:
            if _match_doc(doc, query):
                for op, fields in update.items():
                    if op == "$set":
                        doc.update(fields)
                    elif op == "$inc":
                        for key, value in fields.items():
                            doc[key] = doc.get(key, 0) + value
                modified += 1
        return _UpdateResult(modified_count=modified)

    async def delete_one(self, query):
        for i, doc in enumerate(self._data):
            if all(doc.get(k) == v for k, v in query.items()):
                self._data.pop(i)
                return _DeleteResult(deleted_count=1)
        return _DeleteResult(deleted_count=0)

    async def delete_many(self, query):
        kept = []
        deleted = 0
        for doc in self._data:
            if all(doc.get(k) == v for k, v in query.items()):
                deleted += 1
            else:
                kept.append(doc)
        self._data = kept
        return _DeleteResult(deleted_count=deleted)

    async def count_documents(self, query):
        count = 0
        for doc in self._data:
            match = True
            for k, v in query.items():
                if isinstance(v, dict):
                    doc_val = doc.get(k)
                    if doc_val is None:
                        match = False
                        break
                    if "$gte" in v and doc_val < v["$gte"]:
                        match = False
                        break
                    if "$gt" in v and doc_val <= v["$gt"]:
                        match = False
                        break
                    if "$lte" in v and doc_val > v["$lte"]:
                        match = False
                        break
                    if "$lt" in v and doc_val >= v["$lt"]:
                        match = False
                        break
                    if "$ne" in v and doc_val == v["$ne"]:
                        match = False
                        break
                else:
                    if doc.get(k) != v:
                        match = False
                        break
            if match:
                count += 1
        return count

    async def distinct(self, field, query=None):
        values = []
        for doc in self.find(query)._data:
            value = doc.get(field)
            if value not in values:
                values.append(value)
        return values


class FakeDB:
    def __init__(self):
        self.users = FakeCollection([
            {
                "username": "admin",
                "password_hash": get_password_hash("TestAdmin@1234"),
                "role": "admin",
                "name": "Admin User",
                "email": "admin@soc.local",
                "preferred_lang": "pt",
                "is_active": True,
                "failed_login_count": 0,
                "locked_until": None,
                "last_failed_at": None,
                "password_history": [],
                "password_changed_at": None,
                "force_password_reset": False,
                "last_login_at": None,
                "mfa_enabled": False,
                "mfa_secret_enc": None,
                "mfa_backup_codes": [],
                "extra_permissions": [],
            },
            {
                "username": "inactive",
                "password_hash": get_password_hash("pass"),
                "role": "tech",
                "name": "Inactive",
                "email": None,
                "preferred_lang": "pt",
                "is_active": False,
                "failed_login_count": 0,
                "locked_until": None,
                "last_failed_at": None,
                "password_history": [],
                "password_changed_at": None,
                "force_password_reset": False,
                "last_login_at": None,
                "mfa_enabled": False,
                "mfa_secret_enc": None,
                "mfa_backup_codes": [],
                "extra_permissions": [],
            },
            {
                "username": "techuser",
                "password_hash": get_password_hash("TestTech@9876"),
                "role": "tech",
                "name": "Tech User",
                "email": "tech@soc.local",
                "preferred_lang": "pt",
                "is_active": True,
                "failed_login_count": 0,
                "locked_until": None,
                "last_failed_at": None,
                "password_history": [],
                "password_changed_at": None,
                "force_password_reset": False,
                "last_login_at": None,
                "mfa_enabled": False,
                "mfa_secret_enc": None,
                "mfa_backup_codes": [],
                "extra_permissions": [],
            },
        ])
        self.scans = FakeCollection()
        self.refresh_tokens = FakeCollection()
        self.system_status = FakeCollection()
        self.lockout_policy = FakeCollection()
        self.password_policy = FakeCollection()
        self.audit_log = FakeCollection()
        self.api_keys = FakeCollection()
        self.extension_catalog_state = FakeCollection()
        self.sessions = FakeCollection()
        self.password_reset_tokens = FakeCollection()
        self.operational_config = FakeCollection()
        self.threat_sources = FakeCollection()
        self.threat_sync_status = FakeCollection()
        self.threat_sync_history = FakeCollection()
        self.operational_status_history = FakeCollection()
        self.threat_items = FakeCollection()
        self.hunting_results = FakeCollection()
        self.exposure_monitored_assets = FakeCollection()
        self.exposure_asset_groups = FakeCollection()
        # Extensions platform (Fase 4)
        self.extensions_state = FakeCollection()
        self.extensions_secrets = FakeCollection()
        self.exposure_findings = FakeCollection()
        self.exposure_incidents = FakeCollection()
        self.recon_jobs = FakeCollection()
        self.recon_scheduled = FakeCollection()
        self.recon_results = FakeCollection()
        self.batch_jobs = FakeCollection()
        self.watchlist = FakeCollection()
        self.watchlist_history = FakeCollection()
        self.service_quota = FakeCollection()
        self.custom_threat_sources = FakeCollection()
        self.hunting_saved_searches = FakeCollection()
        self.hunting_case_notes = FakeCollection()
        self.analysis_runtime = FakeCollection()
        self.shift_handoffs = FakeCollection()
        self.shift_handoff_incidents = FakeCollection()
        self.shift_handoff_config = FakeCollection()

    async def create_index(self, *args, **kwargs):
        pass


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_db():
    return FakeDB()


@pytest.fixture(autouse=True)
def disable_rate_limiter(monkeypatch):
    """Disable slowapi rate limiting during tests to prevent cross-test interference."""
    from limiters import limiter
    monkeypatch.setattr(limiter, 'enabled', False)


@pytest_asyncio.fixture
async def async_client(fake_db, monkeypatch):
    """AsyncClient bound to the FastAPI app with a fake database."""
    import app_state
    from db import db_manager
    monkeypatch.setattr(db_manager, "db", fake_db)
    monkeypatch.setattr(app_state, "APP_INITIALIZED", True)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture
def admin_token():
    return create_access_token({"sub": "admin", "role": "admin"})


@pytest.fixture
def tech_token():
    return create_access_token({"sub": "techuser", "role": "tech"})


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
