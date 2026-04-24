#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:

import hashlib
import secrets
import time

from sqlalchemy import BOOLEAN, INTEGER, Column, Integer, String, delete, select, text, update

from db.basedb import AlchemyMixin, BaseDB


class ApiToken(BaseDB, AlchemyMixin):
    __tablename__ = 'api_token'

    id = Column(Integer, primary_key=True)
    userid = Column(INTEGER, nullable=False, index=True)
    name = Column(String(128), nullable=False, server_default=text("''"))
    token_prefix = Column(String(32), nullable=False, index=True)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    scopes = Column(String(1024), nullable=False, server_default=text("''"))
    ctime = Column(INTEGER, nullable=False)
    mtime = Column(INTEGER, nullable=False)
    last_used = Column(INTEGER)
    expires_at = Column(INTEGER)
    revoked = Column(BOOLEAN, nullable=False, server_default=text('0'))

    @staticmethod
    def hash_token(token):
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    @staticmethod
    def generate_token():
        token = secrets.token_urlsafe(32)
        return token, token[:12], ApiToken.hash_token(token)

    async def add_token(self, userid, name='', scopes='', expires_at=None, sql_session=None):
        token, token_prefix, token_hash = self.generate_token()
        now = time.time()
        insert = dict(
            userid=userid,
            name=name,
            token_prefix=token_prefix,
            token_hash=token_hash,
            scopes=scopes,
            ctime=now,
            mtime=now,
            last_used=None,
            expires_at=expires_at,
            revoked=False,
        )
        token_id = await self._insert(ApiToken(**insert), sql_session=sql_session)
        return token_id, token

    def mod(self, id, sql_session=None, **kwargs):
        assert id, 'need id'
        assert 'id' not in kwargs, 'id not modifiable'
        kwargs['mtime'] = time.time()
        return self._update(update(ApiToken).where(ApiToken.id == id).values(**kwargs), sql_session=sql_session)

    async def get(self, id, fields=None, one_or_none=False, first=True, to_dict=True, sql_session=None):
        assert id, 'need id'
        if fields is None:
            _fields = ApiToken
        else:
            _fields = (getattr(ApiToken, field) for field in fields)
        smtm = select(_fields).where(ApiToken.id == id)
        result = await self._get(smtm, one_or_none=one_or_none, first=first, sql_session=sql_session)
        if to_dict and result is not None:
            return self.to_dict(result, fields)
        return result

    async def get_by_hash(self, token_hash, fields=None, one_or_none=False, first=True, to_dict=True, sql_session=None):
        if fields is None:
            _fields = ApiToken
        else:
            _fields = (getattr(ApiToken, field) for field in fields)
        smtm = select(_fields).where(ApiToken.token_hash == token_hash)
        result = await self._get(smtm, one_or_none=one_or_none, first=first, sql_session=sql_session)
        if to_dict and result is not None:
            return self.to_dict(result, fields)
        return result

    async def list(self, userid=None, fields=None, limit=None, to_dict=True, sql_session=None, **kwargs):
        if fields is None:
            _fields = ApiToken
        else:
            _fields = (getattr(ApiToken, field) for field in fields)
        smtm = select(_fields)
        if userid is not None:
            smtm = smtm.where(ApiToken.userid == userid)
        for key, value in kwargs.items():
            smtm = smtm.where(getattr(ApiToken, key) == value)
        if limit:
            smtm = smtm.limit(limit)
        result = await self._get(smtm, sql_session=sql_session)
        if to_dict and result is not None:
            return [self.to_dict(row, fields) for row in result]
        return result

    def revoke(self, id, sql_session=None):
        return self.mod(id, revoked=True, sql_session=sql_session)

    def delete(self, id, sql_session=None):
        return self._delete(delete(ApiToken).where(ApiToken.id == id), sql_session=sql_session)
