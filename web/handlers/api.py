#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:

import datetime
import json
import time

from sqlalchemy.exc import IntegrityError

from Crypto.Hash import MD5
from tornado.escape import json_decode
from tornado.web import HTTPError

import config
from libs import mcrypto as crypto
from libs.funcs import Cal, Pusher
from libs.parse_url import parse_url
from web.handlers.base import BaseHandler
from web.handlers.har import HARSave


class ApiError(HTTPError):
    def __init__(self, status_code, code, message):
        super().__init__(status_code, reason=message)
        self.api_code = code
        self.api_message = message


class ApiBaseHandler(BaseHandler):
    public_routes = {"/api/v1/bootstrap/token"}

    def write_json(self, data=None, status=200):
        self.set_status(status)
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.finish({"ok": True, "data": data})

    def write_error(self, status_code, **kwargs):
        error = kwargs.get("exc_info", (None, None, None))[1]
        code = "error"
        message = self._reason
        if isinstance(error, ApiError):
            code = error.api_code
            message = error.api_message
        elif isinstance(error, HTTPError) and error.log_message:
            message = error.log_message
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.finish({"ok": False, "error": {"code": code, "message": message}})

    def get_current_user(self):
        if hasattr(self, "_api_current_user"):
            return self._api_current_user
        return super().get_current_user()

    def get_json_body(self):
        if not self.request.body:
            return {}
        try:
            return json_decode(self.request.body)
        except Exception as exc:
            raise ApiError(400, "bad_json", "invalid json body") from exc

    def get_scopes(self):
        scopes = self.api_token.get("scopes") or ""
        return set(filter(None, (scope.strip() for scope in scopes.replace(",", " ").split())))

    def require_scope(self, *required_scopes):
        scopes = self.get_scopes()
        if "admin" in scopes:
            return
        raise ApiError(403, "forbidden", "admin scope required")

    def require_admin(self):
        if not self.current_user or self.current_user.get("role") != "admin":
            raise ApiError(403, "forbidden", "admin required")
        if "admin" not in self.get_scopes():
            raise ApiError(403, "forbidden", "admin scope required")

    def sanitize_token(self, token):
        data = dict(token)
        data.pop("token_hash", None)
        return data

    def sanitize_user(self, user, include_sensitive=False):
        data = dict(user)
        for field in ("password", "password_md5", "userkey"):
            data.pop(field, None)
        if not include_sensitive:
            for field in (
                "skey",
                "barkurl",
                "wxpusher",
                "diypusher",
                "qywx_token",
                "qywx_webhook",
                "tg_token",
                "dingding_token",
            ):
                data.pop(field, None)
        return data

    def sanitize_task(self, task):
        data = dict(task)
        for field in ("init_env", "env", "session"):
            data.pop(field, None)
        return data

    def sanitize_tpl(self, tpl):
        data = dict(tpl)
        for field in ("har", "tpl"):
            data.pop(field, None)
        return data

    async def prepare(self):
        if self.request.method == "OPTIONS":
            self.set_status(204)
            self.finish()
            return
        if self.request.path in self.public_routes:
            super().prepare()
            return
        super().prepare()
        auth = self.request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ApiError(401, "unauthorized", "missing bearer token")
        token_value = auth.split(" ", 1)[1].strip()
        if not token_value:
            raise ApiError(401, "unauthorized", "missing bearer token")
        token_hash = self.db.api_token.hash_token(token_value)
        async with self.db.transaction() as sql_session:
            token = await self.db.api_token.get_by_hash(token_hash, sql_session=sql_session)
            if not token or token.get("revoked"):
                self.evil(+5)
                raise ApiError(401, "unauthorized", "invalid token")
            now = time.time()
            if token.get("expires_at") and token["expires_at"] < now:
                raise ApiError(401, "unauthorized", "token expired")
            user = await self.db.user.get(
                token["userid"],
                fields=("id", "email", "nickname", "role", "email_verified", "status"),
                sql_session=sql_session,
            )
            if not user:
                raise ApiError(401, "unauthorized", "user not found")
            if (user.get("status") != "Enable") and (user.get("role") != "admin"):
                raise ApiError(403, "forbidden", "user disabled")
            siteconfig = await self.db.site.get(1, fields=("MustVerifyEmailEn",), sql_session=sql_session)
            must_verify_email_en = siteconfig["MustVerifyEmailEn"] if siteconfig else 0
            if (must_verify_email_en != 0) and (user.get("email_verified") == 0):
                raise ApiError(403, "forbidden", "email not verified")
            user["isadmin"] = user.get("role") == "admin"
            self.api_token = token
            self._api_current_user = user
            self._current_user = user
            await self.db.api_token.mod(token["id"], last_used=now, sql_session=sql_session)


class ApiBootstrapTokenHandler(ApiBaseHandler):
    async def post(self):
        user = self.current_user
        if not user:
            raise ApiError(401, "unauthorized", "login required")
        body = self.get_json_body()
        name = body.get("name", "")
        token_value = body.get("token") or None
        if token_value is not None and not isinstance(token_value, str):
            raise ApiError(400, "bad_request", "token must be a string")
        expires_at = body.get("expires_at")
        try:
            async with self.db.transaction() as sql_session:
                token_id, token = await self.db.api_token.add_token(
                    user["id"],
                    name=name,
                    scopes="admin",
                    expires_at=expires_at,
                    token_value=token_value,
                    sql_session=sql_session,
                )
                token_meta = await self.db.api_token.get(token_id, sql_session=sql_session)
        except IntegrityError as exc:
            raise ApiError(409, "duplicate_token", "token already exists") from exc
        token_meta.pop("token_hash", None)
        token_meta["token"] = token
        self.write_json(token_meta, status=201)


class ApiMeHandler(ApiBaseHandler):
    async def get(self):
        self.write_json(
            {
                "user": self.sanitize_user(self.current_user),
                "token": self.sanitize_token(self.api_token),
                "scopes": sorted(self.get_scopes()),
            }
        )


class ApiTokensHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("token:read")
        userid = self.current_user["id"]
        if self.current_user.get("role") == "admin" and self.get_argument("userid", None):
            self.require_admin()
            userid = int(self.get_argument("userid"))
        tokens = await self.db.api_token.list(userid=userid, limit=None)
        self.write_json([self.sanitize_token(token) for token in tokens])

    async def post(self):
        self.require_scope("token:write")
        body = self.get_json_body()
        userid = self.current_user["id"]
        if body.get("userid") and self.current_user.get("role") == "admin":
            self.require_admin()
            userid = int(body["userid"])
        token_value = body.get("token") or None
        if token_value is not None and not isinstance(token_value, str):
            raise ApiError(400, "bad_request", "token must be a string")
        try:
            async with self.db.transaction() as sql_session:
                token_id, token = await self.db.api_token.add_token(
                    userid,
                    name=body.get("name", ""),
                    scopes="admin",
                    expires_at=body.get("expires_at"),
                    token_value=token_value,
                    sql_session=sql_session,
                )
                token_meta = await self.db.api_token.get(token_id, sql_session=sql_session)
        except IntegrityError as exc:
            raise ApiError(409, "duplicate_token", "token already exists") from exc
        payload = self.sanitize_token(token_meta)
        payload["token"] = token
        self.write_json(payload, status=201)


class ApiTokenDetailHandler(ApiBaseHandler):
    async def get_token(self, token_id, mode="r"):
        token = await self.db.api_token.get(token_id)
        if not token:
            raise ApiError(404, "not_found", "token not found")
        if token["userid"] != self.current_user["id"]:
            self.require_admin()
        if mode == "w":
            self.require_scope("token:write")
        else:
            self.require_scope("token:read")
        return token

    async def get(self, token_id):
        token = await self.get_token(token_id)
        self.write_json(self.sanitize_token(token))

    async def patch(self, token_id):
        token = await self.get_token(token_id, mode="w")
        body = self.get_json_body()
        updates = {}
        for key in ("name", "expires_at"):
            if key in body:
                updates[key] = body[key]
        if "scopes" in body:
            updates["scopes"] = "admin"
        async with self.db.transaction() as sql_session:
            await self.db.api_token.mod(token["id"], sql_session=sql_session, **updates)
            token = await self.db.api_token.get(token["id"], sql_session=sql_session)
        self.write_json(self.sanitize_token(token))

    async def delete(self, token_id):
        token = await self.get_token(token_id, mode="w")
        await self.db.api_token.delete(token["id"])
        self.write_json({"id": token["id"], "deleted": True})


class ApiTasksHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("task:read")
        userid = self.current_user["id"]
        if self.current_user.get("role") == "admin" and self.get_argument("userid", None):
            self.require_admin()
            userid = int(self.get_argument("userid"))
        tasks = await self.db.task.list(userid=userid, limit=None)
        self.write_json([self.sanitize_task(task) for task in tasks])

    async def post(self):
        self.require_scope("task:write")
        body = self.get_json_body()
        tplid = int(body["tplid"])
        note = body.get("note", "")
        proxy = body.get("proxy", "")
        retry_count = body.get("retry_count")
        retry_interval = body.get("retry_interval")
        env = body.get("variables", {}) or {}
        env["_proxy"] = proxy
        env["retry_count"] = retry_count
        env["retry_interval"] = retry_interval
        async with self.db.transaction() as sql_session:
            tpl = self.check_permission(
                await self.db.tpl.get(tplid, fields=("id", "userid", "interval"), sql_session=sql_session)
            )
            encrypted_env = await self.db.user.encrypt(self.current_user["id"], env, sql_session=sql_session)
            taskid = await self.db.task.add(tplid, self.current_user["id"], encrypted_env, sql_session=sql_session)
            await self.db.task.mod(
                taskid,
                note=note,
                next=time.time() + (tpl["interval"] or config.new_task_delay),
                retry_count=retry_count if retry_count is not None else config.task_max_retry_count,
                retry_interval=retry_interval,
                _groups=body.get("group", "None"),
                sql_session=sql_session,
            )
            task = await self.db.task.get(taskid, sql_session=sql_session)
        self.write_json(self.sanitize_task(task), status=201)


class ApiTaskDetailHandler(ApiBaseHandler):
    async def get_task(self, task_id, mode="r", sql_session=None):
        task = self.check_permission(
            await self.db.task.get(task_id, sql_session=sql_session),
            mode,
        )
        return task

    async def get(self, task_id):
        self.require_scope("task:read")
        include_env = self.get_argument("include_env", "false").lower() == "true"
        async with self.db.transaction() as sql_session:
            task = await self.get_task(task_id, sql_session=sql_session)
            data = self.sanitize_task(task)
            if include_env:
                self.require_scope("task:write")
                data["init_env"] = await self.db.user.decrypt(
                    task["userid"], task["init_env"], sql_session=sql_session
                )
        self.write_json(data)

    async def patch(self, task_id):
        self.require_scope("task:write")
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            task = await self.get_task(task_id, mode="w", sql_session=sql_session)
            updates = {}
            for key in ("note", "disabled", "retry_count", "retry_interval", "_groups", "next"):
                if key in body:
                    updates[key] = body[key]
            if "variables" in body or "proxy" in body:
                current_env = await self.db.user.decrypt(task["userid"], task["init_env"], sql_session=sql_session)
                current_env.update(body.get("variables", {}))
                if "proxy" in body:
                    current_env["_proxy"] = body.get("proxy", "")
                updates["init_env"] = await self.db.user.encrypt(task["userid"], current_env, sql_session=sql_session)
                updates["env"] = None
                updates["session"] = None
            await self.db.task.mod(task["id"], sql_session=sql_session, **updates)
            task = await self.db.task.get(task["id"], sql_session=sql_session)
        self.write_json(self.sanitize_task(task))

    async def delete(self, task_id):
        self.require_scope("task:write")
        async with self.db.transaction() as sql_session:
            task = await self.get_task(task_id, mode="w", sql_session=sql_session)
            logs = await self.db.tasklog.list(taskid=task["id"], fields=("id",), limit=None, sql_session=sql_session)
            for log in logs:
                await self.db.tasklog.delete(log["id"], sql_session=sql_session)
            await self.db.task.delete(task["id"], sql_session=sql_session)
        self.write_json({"id": int(task_id), "deleted": True})


class ApiTaskSwitchHandler(ApiBaseHandler):
    async def post(self, task_id, action):
        self.require_scope("task:write")
        disabled = action == "disable"
        async with self.db.transaction() as sql_session:
            task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session), "w")
            await self.db.task.mod(task["id"], disabled=disabled, sql_session=sql_session)
            task = await self.db.task.get(task["id"], sql_session=sql_session)
        self.write_json(self.sanitize_task(task))


class ApiTaskScheduleHandler(ApiBaseHandler):
    async def patch(self, task_id):
        self.require_scope("task:write")
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session), "w")
            cal = Cal()
            schedule = body.copy()
            if schedule.get("sw") and "time" in schedule and len(schedule["time"].split(":")) < 3:
                schedule["time"] = schedule["time"] + ":00"
            if schedule.get("sw"):
                result = cal.cal_next_ts(schedule)
                if result["r"] != "True":
                    raise ApiError(400, "bad_request", result["r"])
                await self.db.task.mod(task["id"], disabled=False, newontime=json.dumps(schedule), next=result["ts"], sql_session=sql_session)
            else:
                current = json.loads(task["newontime"])
                current["sw"] = False
                await self.db.task.mod(task["id"], newontime=json.dumps(current), sql_session=sql_session)
            task = await self.db.task.get(task["id"], sql_session=sql_session)
        self.write_json(self.sanitize_task(task))


class ApiTaskGroupHandler(ApiBaseHandler):
    async def patch(self, task_id):
        self.require_scope("task:write")
        body = self.get_json_body()
        group = body.get("group", "None") or "None"
        async with self.db.transaction() as sql_session:
            task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session), "w")
            await self.db.task.mod(task["id"], _groups=group, sql_session=sql_session)
            task = await self.db.task.get(task["id"], sql_session=sql_session)
        self.write_json(self.sanitize_task(task))


class ApiTaskRunHandler(ApiBaseHandler):
    async def post(self, task_id):
        self.require_scope("task:run")
        self.evil(+2)
        start_ts = int(time.time())
        async with self.db.transaction() as sql_session:
            task = self.check_permission(
                await self.db.task.get(task_id, sql_session=sql_session),
                "w",
            )
            tpl = self.check_permission(
                await self.db.tpl.get(task["tplid"], fields=("id", "userid", "sitename", "siteurl", "tpl", "interval"), sql_session=sql_session)
            )
            fetch_tpl = await self.db.user.decrypt(
                0 if not tpl["userid"] else task["userid"],
                tpl["tpl"],
                sql_session=sql_session,
            )
            env = {
                "variables": await self.db.user.decrypt(task["userid"], task["init_env"], sql_session=sql_session),
                "session": [],
            }
            pushsw = json.loads(task["pushsw"])
            newontime = json.loads(task["newontime"])
            pushertool = Pusher(self.db, sql_session=sql_session)
            caltool = Cal()
            try:
                url = parse_url(env["variables"].get("_proxy", ""))
                if url:
                    proxy = {
                        "scheme": url["scheme"],
                        "host": url["host"],
                        "port": url["port"],
                        "username": url["username"],
                        "password": url["password"],
                    }
                    new_env, _ = await self.fetcher.do_fetch(fetch_tpl, env, [proxy])
                else:
                    new_env, _ = await self.fetcher.do_fetch(fetch_tpl, env)
            except Exception as exc:
                await self.db.tasklog.add(task["id"], success=False, msg=str(exc), sql_session=sql_session)
                await self.db.task.mod(
                    task["id"],
                    last_failed=time.time(),
                    failed_count=task["failed_count"] + 1,
                    last_failed_count=task["last_failed_count"] + 1,
                    sql_session=sql_session,
                )
                title = f"QD任务 {tpl['sitename']}-{task['note']} 失败"
                logtmp = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \\r\\n日志：{exc}"
                await pushertool.pusher(self.current_user["id"], pushsw, 0x4, title, logtmp)
                self.write_json({"task_id": task["id"], "success": False, "log": str(exc)}, status=200)
                return
            await self.db.tasklog.add(task["id"], success=True, msg=new_env["variables"].get("__log__"), sql_session=sql_session)
            if newontime["sw"]:
                if "mode" not in newontime:
                    newontime["mode"] = "ontime"
                if newontime["mode"] == "ontime":
                    newontime["date"] = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
                next_time = caltool.cal_next_ts(newontime)["ts"]
            else:
                next_time = time.time() + (tpl["interval"] if tpl["interval"] else 24 * 60 * 60)
            await self.db.task.mod(
                task["id"],
                disabled=False,
                last_success=time.time(),
                last_failed_count=0,
                success_count=task["success_count"] + 1,
                next=next_time,
                sql_session=sql_session,
            )
            await self.db.tpl.incr_success(tpl["id"], sql_session=sql_session)
            log_day = int((await self.db.site.get(1, fields=("logDay",), sql_session=sql_session))["logDay"])
            for log in await self.db.tasklog.list(taskid=task_id, fields=("id", "ctime"), limit=None, sql_session=sql_session):
                if (time.time() - log["ctime"]) > (log_day * 24 * 60 * 60):
                    await self.db.tasklog.delete(log["id"], sql_session=sql_session)
            title = f"QD任务 {tpl['sitename']}-{task['note']} 成功"
            logtmp = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \\r\\n日志：{new_env['variables'].get('__log__')}"
        await pushertool.pusher(self.current_user["id"], pushsw, 0x8, title, logtmp)
        self.write_json(
            {
                "task_id": task["id"],
                "tpl_id": task["tplid"],
                "success": True,
                "log": new_env["variables"].get("__log__"),
                "next": next_time,
                "duration": round(time.time() - start_ts, 4),
            }
        )


class ApiTaskLogsHandler(ApiBaseHandler):
    async def get(self, task_id):
        self.require_scope("log:read")
        async with self.db.transaction() as sql_session:
            task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session))
            logs = await self.db.tasklog.list(taskid=task["id"], limit=None, sql_session=sql_session)
        self.write_json(logs)

    async def delete(self, task_id):
        self.require_scope("log:write")
        body = self.get_json_body()
        older_than_days = int(body.get("older_than_days", 0))
        success_filter = body.get("success")
        async with self.db.transaction() as sql_session:
            task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session), "w")
            logs = await self.db.tasklog.list(taskid=task["id"], limit=None, sql_session=sql_session)
            deleted = 0
            for log in logs:
                if older_than_days and (time.time() - log["ctime"]) <= older_than_days * 24 * 60 * 60:
                    continue
                if success_filter is not None and bool(log["success"]) != bool(success_filter):
                    continue
                await self.db.tasklog.delete(log["id"], sql_session=sql_session)
                deleted += 1
        self.write_json({"task_id": int(task_id), "deleted": deleted})




class ApiLogsHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("log:read")
        userid = self.current_user["id"]
        if self.current_user.get("role") == "admin" and self.get_argument("userid", None):
            self.require_admin()
            userid = int(self.get_argument("userid"))
        days = int(self.get_argument("days", 365))
        result = []
        async with self.db.transaction() as sql_session:
            tasks = await self.db.task.list(userid, fields=("id", "tplid", "note"), limit=None, sql_session=sql_session)
            for task in tasks:
                logs = await self.db.tasklog.list(taskid=task["id"], fields=("id", "success", "ctime", "msg"), limit=None, sql_session=sql_session)
                for log in logs:
                    if (time.time() - log["ctime"]) <= (days * 24 * 60 * 60):
                        item = dict(log)
                        item["task"] = task
                        result.append(item)
        self.write_json(result)




class ApiTemplatesHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("template:read")
        scope = self.get_argument("scope", "mine")
        if scope == "public":
            tpls = await self.db.tpl.list(userid=None, public=1, limit=None)
        elif scope == "all":
            self.require_admin()
            tpls = await self.db.tpl.list(limit=None)
        else:
            tpls = await self.db.tpl.list(userid=self.current_user["id"], limit=None)
        self.write_json([self.sanitize_tpl(tpl) for tpl in tpls])

    async def post(self):
        self.require_scope("template:write")
        body = self.get_json_body()
        tpl_data = body["tpl"]
        har_data = body.get("har", [])
        async with self.db.transaction() as sql_session:
            har = await self.db.user.encrypt(self.current_user["id"], har_data, sql_session=sql_session)
            tpl = await self.db.user.encrypt(self.current_user["id"], tpl_data, sql_session=sql_session)
            variables = json.dumps(list(HARSave.get_variables(HARSave.env, tpl_data)))
            init_env = json.dumps(body.get("init_env", {}))
            tplid = await self.db.tpl.add(self.current_user["id"], har, tpl, variables, init_env=init_env, sql_session=sql_session)
            await self.db.tpl.mod(
                tplid,
                siteurl=body.get("siteurl"),
                sitename=body.get("sitename"),
                banner=body.get("banner"),
                note=body.get("note"),
                interval=body.get("interval"),
                public=body.get("public", 0),
                _groups=body.get("group", "None"),
                sql_session=sql_session,
            )
            tpl_obj = await self.db.tpl.get(tplid, sql_session=sql_session)
        self.write_json(self.sanitize_tpl(tpl_obj), status=201)


class ApiTemplateDetailHandler(ApiBaseHandler):
    async def get_tpl(self, tpl_id, mode="r", sql_session=None):
        tpl = await self.db.tpl.get(tpl_id, sql_session=sql_session)
        if not tpl:
            raise ApiError(404, "not_found", "template not found")
        if mode == "w":
            tpl = self.check_permission(tpl, "w")
            if not tpl["userid"]:
                raise ApiError(403, "forbidden", "public template is read only")
            if tpl.get("lock"):
                raise ApiError(403, "forbidden", "template is locked")
            self.require_scope("template:write")
        else:
            self.check_permission(tpl)
            self.require_scope("template:read")
        return tpl

    async def get(self, tpl_id):
        include_content = self.get_argument("include_content", "false").lower() == "true"
        async with self.db.transaction() as sql_session:
            tpl = await self.get_tpl(tpl_id, sql_session=sql_session)
            data = self.sanitize_tpl(tpl)
            if include_content:
                self.require_scope("template:write")
                data["har"] = await self.db.user.decrypt(tpl["userid"], tpl["har"], sql_session=sql_session)
                data["tpl"] = await self.db.user.decrypt(tpl["userid"], tpl["tpl"], sql_session=sql_session)
                data["init_env"] = json.loads(tpl["init_env"] or "{}")
        self.write_json(data)

    async def patch(self, tpl_id):
        self.require_scope("template:write")
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            tpl = await self.get_tpl(tpl_id, mode="w", sql_session=sql_session)
            updates = {}
            for key in ("siteurl", "sitename", "banner", "note", "interval", "public", "disabled", "_groups"):
                if key in body:
                    updates[key] = body[key]
            if "group" in body:
                updates["_groups"] = body["group"] or "None"
            if "tpl" in body:
                updates["tpl"] = await self.db.user.encrypt(tpl["userid"], body["tpl"], sql_session=sql_session)
                variables = list(HARSave.get_variables(HARSave.env, body["tpl"]))
                updates["variables"] = json.dumps(variables)
            if "har" in body:
                updates["har"] = await self.db.user.encrypt(tpl["userid"], body["har"], sql_session=sql_session)
            if "init_env" in body:
                updates["init_env"] = json.dumps(body["init_env"] or {})
            await self.db.tpl.mod(tpl["id"], sql_session=sql_session, **updates)
            tpl = await self.db.tpl.get(tpl["id"], sql_session=sql_session)
        self.write_json(self.sanitize_tpl(tpl))

    async def delete(self, tpl_id):
        self.require_scope("template:write")
        async with self.db.transaction() as sql_session:
            tpl = await self.get_tpl(tpl_id, mode="w", sql_session=sql_session)
            if tpl["public"] == 1:
                prs = await self.db.push_request.list(to_tplid=tpl_id, fields=("id",), sql_session=sql_session)
                for pr in prs:
                    await self.db.push_request.mod(pr["id"], status=self.db.push_request.CANCEL, sql_session=sql_session)
            tasks = await self.db.task.list(fields=("id",), limit=None, tplid=tpl["id"], sql_session=sql_session)
            for task in tasks:
                logs = await self.db.tasklog.list(taskid=task["id"], fields=("id",), limit=None, sql_session=sql_session)
                for log in logs:
                    await self.db.tasklog.delete(log["id"], sql_session=sql_session)
                await self.db.task.delete(task["id"], sql_session=sql_session)
            await self.db.tpl.delete(tpl["id"], sql_session=sql_session)
        self.write_json({"id": int(tpl_id), "deleted": True})


class ApiTemplateVariablesHandler(ApiBaseHandler):
    async def get(self, tpl_id):
        self.require_scope("template:read")
        async with self.db.transaction() as sql_session:
            tpl = self.check_permission(
                await self.db.tpl.get(tpl_id, fields=("id", "userid", "variables", "init_env"), sql_session=sql_session)
            )
            init_env = json.loads(tpl["init_env"] or "{}")
            variables = json.loads(tpl["variables"] or "[]")
        self.write_json({"variables": variables, "init_env": init_env})


class ApiTemplateRunHandler(ApiBaseHandler):
    async def post(self, tpl_id):
        self.require_scope("template:run")
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            tpl = self.check_permission(
                await self.db.tpl.get(
                    tpl_id,
                    fields=("id", "userid", "sitename", "siteurl", "tpl", "interval", "last_success"),
                    sql_session=sql_session,
                )
            )
            fetch_tpl = await self.db.user.decrypt(tpl["userid"], tpl["tpl"], sql_session=sql_session)
            env = {
                "variables": body.get("variables", {}),
                "session": body.get("session", []),
            }
            try:
                url = parse_url(env["variables"].get("_proxy", ""))
                if url:
                    proxy = {
                        "scheme": url["scheme"],
                        "host": url["host"],
                        "port": url["port"],
                        "username": url["username"],
                        "password": url["password"],
                    }
                    result, _ = await self.fetcher.do_fetch(fetch_tpl, env, [proxy])
                else:
                    result, _ = await self.fetcher.do_fetch(fetch_tpl, env)
            except Exception as exc:
                raise ApiError(400, "run_failed", str(exc)) from exc
            await self.db.tpl.incr_success(tpl["id"], sql_session=sql_session)
        self.write_json({
            "template_id": tpl["id"],
            "success": True,
            "log": result.get("variables", {}).get("__log__"),
            "variables": result.get("variables", {}),
        })


class ApiTaskBatchHandler(ApiBaseHandler):
    async def post(self):
        self.require_scope("task:write")
        body = self.get_json_body()
        action = body.get("action")
        task_ids = body.get("task_ids") or []
        if not isinstance(task_ids, list) or not task_ids:
            raise ApiError(400, "bad_request", "task_ids required")
        result = {"updated": [], "deleted": []}
        async with self.db.transaction() as sql_session:
            for task_id in task_ids:
                task = self.check_permission(await self.db.task.get(task_id, sql_session=sql_session), "w")
                if action == "delete":
                    logs = await self.db.tasklog.list(taskid=task["id"], fields=("id",), limit=None, sql_session=sql_session)
                    for log in logs:
                        await self.db.tasklog.delete(log["id"], sql_session=sql_session)
                    await self.db.task.delete(task["id"], sql_session=sql_session)
                    result["deleted"].append(task["id"])
                elif action == "enable":
                    await self.db.task.mod(task["id"], disabled=False, sql_session=sql_session)
                    result["updated"].append(task["id"])
                elif action == "disable":
                    await self.db.task.mod(task["id"], disabled=True, sql_session=sql_session)
                    result["updated"].append(task["id"])
                elif action == "set_group":
                    await self.db.task.mod(task["id"], _groups=(body.get("group") or "None"), sql_session=sql_session)
                    result["updated"].append(task["id"])
                else:
                    raise ApiError(400, "bad_request", "unsupported batch action")
        self.write_json(result)


class ApiUsersHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("user:read")
        self.require_admin()
        include_sensitive = self.get_argument("include_sensitive", "false").lower() == "true"
        users = await self.db.user.list(limit=None)
        self.write_json([self.sanitize_user(user, include_sensitive=include_sensitive) for user in users])

    async def post(self):
        self.require_scope("user:write")
        self.require_admin()
        body = self.get_json_body()
        email = body.get("email")
        password = body.get("password")
        if not email or not password:
            raise ApiError(400, "bad_request", "email and password required")
        if email.count("@") != 1 or email.count(".") == 0:
            raise ApiError(400, "bad_request", "invalid email")
        if len(password) < 6:
            raise ApiError(400, "bad_request", "password too short")
        async with self.db.transaction() as sql_session:
            try:
                await self.db.user.add(email=email, password=password, ip=self.ip2varbinary, sql_session=sql_session)
            except self.db.user.DeplicateUser as exc:
                raise ApiError(409, "conflict", "email already exists") from exc
            user = await self.db.user.get(email=email, fields=("id",), sql_session=sql_session)
            await self.db.notepad.add(dict(userid=user["id"], notepadid=1), sql_session=sql_session)
            updates = {}
            for key in ("nickname", "role", "status", "email_verified"):
                if key in body:
                    updates[key] = body[key]
            if updates:
                await self.db.user.mod(user["id"], sql_session=sql_session, **updates)
            user = await self.db.user.get(user["id"], sql_session=sql_session)
        self.write_json(self.sanitize_user(user), status=201)


class ApiUserDetailHandler(ApiBaseHandler):
    async def get_user(self, user_id, mode="r", sql_session=None):
        if self.current_user.get("id") != int(user_id):
            self.require_admin()
        if mode == "w":
            self.require_scope("user:write")
        else:
            self.require_scope("user:read")
        user = await self.db.user.get(user_id, sql_session=sql_session)
        if not user:
            raise ApiError(404, "not_found", "user not found")
        return user

    async def get(self, user_id):
        include_sensitive = self.get_argument("include_sensitive", "false").lower() == "true"
        async with self.db.transaction() as sql_session:
            user = await self.get_user(user_id, sql_session=sql_session)
        if include_sensitive and self.current_user.get("id") != int(user_id):
            self.require_admin()
        self.write_json(self.sanitize_user(user, include_sensitive=include_sensitive))

    async def patch(self, user_id):
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            user = await self.get_user(user_id, mode="w", sql_session=sql_session)
            updates = {}
            for key in (
                "nickname",
                "role",
                "status",
                "email_verified",
                "noticeflg",
                "logtime",
                "push_batch",
                "diypusher",
            ):
                if key in body:
                    updates[key] = json.dumps(body[key]) if key in ("logtime", "push_batch", "diypusher") and not isinstance(body[key], str) else body[key]
            if self.current_user.get("id") == int(user_id):
                updates.pop("role", None)
                updates.pop("status", None)
                if "email_verified" in updates and not self.current_user.get("isadmin"):
                    updates.pop("email_verified", None)
            for key in ("skey", "barkurl", "wxpusher", "qywx_token", "qywx_webhook", "tg_token", "dingding_token"):
                if key in body:
                    if self.current_user.get("id") != int(user_id):
                        self.require_admin()
                    updates[key] = body[key]
            if updates:
                await self.db.user.mod(user["id"], sql_session=sql_session, **updates)
            user = await self.db.user.get(user["id"], sql_session=sql_session)
        include_sensitive = self.current_user.get("id") == int(user_id) or self.current_user.get("isadmin")
        self.write_json(self.sanitize_user(user, include_sensitive=include_sensitive))

    async def delete(self, user_id):
        self.require_scope("user:write")
        self.require_admin()
        async with self.db.transaction() as sql_session:
            user = await self.db.user.get(user_id, fields=("id", "role"), sql_session=sql_session)
            if not user:
                raise ApiError(404, "not_found", "user not found")
            if user.get("role") == "admin":
                raise ApiError(403, "forbidden", "cannot delete admin user")
            tasks = await self.db.task.list(user_id, fields=("id",), limit=None, sql_session=sql_session)
            for task in tasks:
                logs = await self.db.tasklog.list(taskid=task["id"], fields=("id",), limit=None, sql_session=sql_session)
                for log in logs:
                    await self.db.tasklog.delete(log["id"], sql_session=sql_session)
                await self.db.task.delete(task["id"], sql_session=sql_session)
            tpls = await self.db.tpl.list(userid=int(user_id), fields=("id",), limit=None, sql_session=sql_session)
            for tpl in tpls:
                await self.db.tpl.delete(tpl["id"], sql_session=sql_session)
            notepads = await self.db.notepad.list(fields=("notepadid",), limit=None, userid=int(user_id), sql_session=sql_session)
            for notepad in notepads:
                await self.db.notepad.delete(int(user_id), notepad["notepadid"], sql_session=sql_session)
            await self.db.user.delete(int(user_id), sql_session=sql_session)
        self.write_json({"id": int(user_id), "deleted": True})


class ApiUserPasswordHandler(ApiUserDetailHandler):
    async def post(self, user_id):
        body = self.get_json_body()
        password = body.get("password")
        if not password or len(password) < 6:
            raise ApiError(400, "bad_request", "password too short")
        async with self.db.transaction() as sql_session:
            await self.get_user(user_id, mode="w", sql_session=sql_session)
            await self.db.user.mod(int(user_id), password=password, sql_session=sql_session)
            user = await self.db.user.get(int(user_id), fields=("password", "password_md5"), sql_session=sql_session)
            hash_md5 = MD5.new()
            hash_md5.update(password.encode("utf-8"))
            password_md5 = crypto.password_hash(
                hash_md5.hexdigest(),
                await self.db.user.decrypt(int(user_id), user["password"], sql_session=sql_session),
            )
            if user["password_md5"] != password_md5:
                await self.db.user.mod(int(user_id), password_md5=password_md5, sql_session=sql_session)
        self.write_json({"id": int(user_id), "password_updated": True})


class ApiUserPushHandler(ApiUserDetailHandler):
    async def patch(self, user_id):
        body = self.get_json_body()
        async with self.db.transaction() as sql_session:
            await self.get_user(user_id, mode="w", sql_session=sql_session)
            updates = {}
            for key in (
                "skey",
                "barkurl",
                "wxpusher",
                "qywx_token",
                "qywx_webhook",
                "tg_token",
                "dingding_token",
                "noticeflg",
                "logtime",
                "push_batch",
                "diypusher",
            ):
                if key in body:
                    value = body[key]
                    if key in ("logtime", "push_batch", "diypusher") and not isinstance(value, str):
                        value = json.dumps(value)
                    updates[key] = value
            if not updates:
                raise ApiError(400, "bad_request", "no push settings provided")
            await self.db.user.mod(int(user_id), sql_session=sql_session, **updates)
            user = await self.db.user.get(int(user_id), sql_session=sql_session)
        self.write_json(self.sanitize_user(user, include_sensitive=True))


class ApiSiteConfigHandler(ApiBaseHandler):
    async def get(self):
        self.require_scope("site:read")
        self.require_admin()
        site = await self.db.site.get(1)
        self.write_json(site)

    async def patch(self):
        self.require_scope("site:write")
        self.require_admin()
        body = self.get_json_body()
        updates = {}
        for key in ("regEn", "MustVerifyEmailEn", "logDay", "repos"):
            if key in body:
                updates[key] = json.dumps(body[key], ensure_ascii=False, indent=4) if key == "repos" and not isinstance(body[key], str) else body[key]
        if updates.get("MustVerifyEmailEn") == 1 and not config.domain:
            raise ApiError(400, "bad_request", "config.domain is required for email verification")
        async with self.db.transaction() as sql_session:
            await self.db.site.mod(1, sql_session=sql_session, **updates)
            site = await self.db.site.get(1, sql_session=sql_session)
        self.write_json(site)


handlers = [
    (r"/api/v1/bootstrap/token", ApiBootstrapTokenHandler),
    (r"/api/v1/me", ApiMeHandler),
    (r"/api/v1/tokens", ApiTokensHandler),
    (r"/api/v1/tokens/(\d+)", ApiTokenDetailHandler),
    (r"/api/v1/tasks", ApiTasksHandler),
    (r"/api/v1/tasks/batch", ApiTaskBatchHandler),
    (r"/api/v1/tasks/(\d+)", ApiTaskDetailHandler),
    (r"/api/v1/tasks/(\d+)/(enable|disable)", ApiTaskSwitchHandler),
    (r"/api/v1/tasks/(\d+)/schedule", ApiTaskScheduleHandler),
    (r"/api/v1/tasks/(\d+)/group", ApiTaskGroupHandler),
    (r"/api/v1/tasks/(\d+)/run", ApiTaskRunHandler),
    (r"/api/v1/tasks/(\d+)/logs", ApiTaskLogsHandler),
    (r"/api/v1/logs", ApiLogsHandler),
    (r"/api/v1/templates", ApiTemplatesHandler),
    (r"/api/v1/templates/(\d+)", ApiTemplateDetailHandler),
    (r"/api/v1/templates/(\d+)/variables", ApiTemplateVariablesHandler),
    (r"/api/v1/templates/(\d+)/run", ApiTemplateRunHandler),
    (r"/api/v1/users", ApiUsersHandler),
    (r"/api/v1/users/(\d+)", ApiUserDetailHandler),
    (r"/api/v1/users/(\d+)/password", ApiUserPasswordHandler),
    (r"/api/v1/users/(\d+)/push", ApiUserPushHandler),
    (r"/api/v1/site/config", ApiSiteConfigHandler),
]
