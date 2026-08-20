# UC-001 SuperAdmin Login Runtime Error

```text
{"level":"error","timestamp":"2026-08-20T11:08:45.339968140Z","message":"    await self.app(scope, receive, send)"}
{"timestamp":"2026-08-20T11:08:45.339973353Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/routing.py\", line 670, in __call__"}
{"message":"    await self.middleware_stack(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.339978778Z"}
{"timestamp":"2026-08-20T11:08:45.339984305Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 2734, in app"}
{"message":"    await route.handle(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.339989779Z"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1780, in handle","timestamp":"2026-08-20T11:08:45.339995167Z"}
{"message":"    await self.original_router.handle(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.340001278Z"}
{"timestamp":"2026-08-20T11:08:45.340006903Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 2789, in handle"}
{"message":"    await included_router._handle_selected(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.340012067Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1800, in _handle_selected","timestamp":"2026-08-20T11:08:45.340017710Z","level":"error"}
{"message":"    await original_route.handle(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.340022397Z"}
{"timestamp":"2026-08-20T11:08:45.340027125Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1279, in handle","level":"error"}
{"level":"error","message":"    await app(scope, receive, send)","timestamp":"2026-08-20T11:08:45.340032205Z"}
{"level":"error","timestamp":"2026-08-20T11:08:45.340038616Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 158, in app"}
{"level":"error","message":"    await wrap_app_handling_exceptions(app, request)(scope, receive, send)","timestamp":"2026-08-20T11:08:45.340049684Z"}
{"level":"error","message":"    return await anyio.to_thread.run_sync(func)","timestamp":"2026-08-20T11:08:45.341129918Z"}
{"message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.341145716Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.341147427Z","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 53, in wrapped_app","level":"error"}
{"timestamp":"2026-08-20T11:08:45.341155686Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/to_thread.py\", line 65, in run_sync"}
{"message":"    raise exc","timestamp":"2026-08-20T11:08:45.341165001Z","level":"error"}
{"message":"    return await get_async_backend().run_sync_in_worker_thread(","timestamp":"2026-08-20T11:08:45.341168606Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 42, in wrapped_app","level":"error","timestamp":"2026-08-20T11:08:45.341173673Z"}
{"level":"error","timestamp":"2026-08-20T11:08:45.341181560Z","message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"}
{"timestamp":"2026-08-20T11:08:45.341181649Z","message":"    await app(scope, receive, sender)","level":"error"}
{"timestamp":"2026-08-20T11:08:45.341187818Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 144, in app"}
{"message":"    response = await f(request)","timestamp":"2026-08-20T11:08:45.341195489Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.341199638Z","message":"               ^^^^^^^^^^^^^^^^","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.341204177Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 706, in app"}
{"timestamp":"2026-08-20T11:08:45.341208522Z","level":"error","message":"    raw_response = await run_endpoint_function("}
{"timestamp":"2026-08-20T11:08:45.341213261Z","level":"error","message":"                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^"}
{"timestamp":"2026-08-20T11:08:45.341217276Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 354, in run_endpoint_function","level":"error"}
{"message":"    return await run_in_threadpool(dependant.call, **values)","timestamp":"2026-08-20T11:08:45.341221306Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.341226059Z","level":"error","message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"}
{"timestamp":"2026-08-20T11:08:45.341230462Z","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/concurrency.py\", line 34, in run_in_threadpool","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/applications.py\", line 1163, in __call__","timestamp":"2026-08-20T11:08:45.342636347Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/_backends/_asyncio.py\", line 2641, in run_sync_in_worker_thread","timestamp":"2026-08-20T11:08:45.342663764Z","level":"error"}
{"message":"    return await future","timestamp":"2026-08-20T11:08:45.342678082Z","level":"error"}
{"message":"           ^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.342683134Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.342687600Z","message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/_backends/_asyncio.py\", line 1033, in run"}
{"timestamp":"2026-08-20T11:08:45.342692666Z","level":"error","message":"    result = context.run(func, *args)"}
{"timestamp":"2026-08-20T11:08:45.342697517Z","level":"error","message":"             ^^^^^^^^^^^^^^^^^^^^^^^^"}
{"timestamp":"2026-08-20T11:08:45.342703327Z","message":"  File \"/usr/local/lib/python3.12/site-packages/verigence_security/api/routes/access.py\", line 169, in credential_login","level":"error"}
{"timestamp":"2026-08-20T11:08:45.342707505Z","level":"error","message":"    raise RuntimeError(\"Configured Security human access-token lifetime is unavailable\")"}
{"timestamp":"2026-08-20T11:08:45.342711979Z","message":"RuntimeError: Configured Security human access-token lifetime is unavailable","level":"error"}
{"message":"INFO:     100.64.0.4:15590 - \"POST /security/v1/auth/login HTTP/1.1\" 500 Internal Server Error","timestamp":"2026-08-20T11:08:45.342717085Z","level":"info"}
{"timestamp":"2026-08-20T11:08:45.342721199Z","level":"error","message":"ERROR:    Exception in ASGI application"}
{"level":"error","timestamp":"2026-08-20T11:08:45.342726281Z","message":"Traceback (most recent call last):"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/uvicorn/protocols/http/httptools_impl.py\", line 422, in run_asgi","timestamp":"2026-08-20T11:08:45.342730649Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.342735539Z","message":"    result = await app(  # type: ignore[func-returns-value]"}
{"level":"error","message":"             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.342740383Z"}
{"timestamp":"2026-08-20T11:08:45.342744783Z","message":"  File \"/usr/local/lib/python3.12/site-packages/uvicorn/middleware/proxy_headers.py\", line 63, in __call__","level":"error"}
{"message":"    return await self.app(scope, receive, send)","level":"error","timestamp":"2026-08-20T11:08:45.342748876Z"}
{"message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.342753292Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.343699955Z","message":"    await super().__call__(scope, receive, send)"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/applications.py\", line 96, in __call__","timestamp":"2026-08-20T11:08:45.343710591Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.343716153Z","message":"    await self.middleware_stack(scope, receive, send)"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/errors.py\", line 186, in __call__","timestamp":"2026-08-20T11:08:45.343722007Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.343728220Z","message":"    raise exc"}
{"level":"error","timestamp":"2026-08-20T11:08:45.343736175Z","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/errors.py\", line 164, in __call__"}
{"level":"error","timestamp":"2026-08-20T11:08:45.343742030Z","message":"    await self.app(scope, receive, _send)"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/base.py\", line 193, in __call__","timestamp":"2026-08-20T11:08:45.343747804Z"}
{"timestamp":"2026-08-20T11:08:45.343753655Z","level":"error","message":"    response = await self.dispatch_func(request, call_next)"}
{"timestamp":"2026-08-20T11:08:45.343760332Z","level":"error","message":"               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/verigence_security/core/correlation.py\", line 59, in dispatch","timestamp":"2026-08-20T11:08:45.343767300Z"}
{"timestamp":"2026-08-20T11:08:45.343773538Z","level":"error","message":"    response = await call_next(request)"}
{"timestamp":"2026-08-20T11:08:45.343787740Z","level":"error","message":"               ^^^^^^^^^^^^^^^^^^^^^^^^"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/base.py\", line 168, in call_next","timestamp":"2026-08-20T11:08:45.343793965Z"}
{"timestamp":"2026-08-20T11:08:45.343799977Z","level":"error","message":"    raise app_exc from app_exc.__cause__ or app_exc.__context__"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/base.py\", line 144, in coro","level":"error","timestamp":"2026-08-20T11:08:45.343805608Z"}
{"timestamp":"2026-08-20T11:08:45.343813742Z","level":"error","message":"    await self.app(scope, receive_or_disconnect, send_no_error)"}
{"timestamp":"2026-08-20T11:08:45.343820572Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/middleware/exceptions.py\", line 63, in __call__"}
{"level":"error","message":"    await self.original_router.handle(scope, receive, send)","timestamp":"2026-08-20T11:08:45.345102370Z"}
{"message":"    await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)","timestamp":"2026-08-20T11:08:45.345109082Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.345110478Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 2789, in handle"}
{"level":"error","timestamp":"2026-08-20T11:08:45.345117793Z","message":"    await included_router._handle_selected(scope, receive, send)"}
{"timestamp":"2026-08-20T11:08:45.345121508Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 53, in wrapped_app"}
{"timestamp":"2026-08-20T11:08:45.345124554Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1800, in _handle_selected","level":"error"}
{"message":"    await original_route.handle(scope, receive, send)","timestamp":"2026-08-20T11:08:45.345132670Z","level":"error"}
{"message":"    raise exc","timestamp":"2026-08-20T11:08:45.345133292Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1279, in handle","timestamp":"2026-08-20T11:08:45.345137715Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 42, in wrapped_app","timestamp":"2026-08-20T11:08:45.345144286Z","level":"error"}
{"level":"error","timestamp":"2026-08-20T11:08:45.345150013Z","message":"    await app(scope, receive, sender)"}
{"level":"error","timestamp":"2026-08-20T11:08:45.345156020Z","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/middleware/asyncexitstack.py\", line 18, in __call__"}
{"level":"error","timestamp":"2026-08-20T11:08:45.345161169Z","message":"    await self.app(scope, receive, send)"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/routing.py\", line 670, in __call__","timestamp":"2026-08-20T11:08:45.345166353Z"}
{"level":"error","message":"    await self.middleware_stack(scope, receive, send)","timestamp":"2026-08-20T11:08:45.345172243Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 2734, in app","timestamp":"2026-08-20T11:08:45.345178455Z","level":"error"}
{"message":"    await route.handle(scope, receive, send)","timestamp":"2026-08-20T11:08:45.345184178Z","level":"error"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 1780, in handle","timestamp":"2026-08-20T11:08:45.345189372Z"}
{"level":"error","message":"    await app(scope, receive, send)","timestamp":"2026-08-20T11:08:45.346261026Z"}
{"timestamp":"2026-08-20T11:08:45.346270187Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 158, in app"}
{"message":"    await wrap_app_handling_exceptions(app, request)(scope, receive, send)","timestamp":"2026-08-20T11:08:45.346275462Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 53, in wrapped_app","level":"error","timestamp":"2026-08-20T11:08:45.346279946Z"}
{"level":"error","message":"    raise exc","timestamp":"2026-08-20T11:08:45.346284573Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/_exception_handler.py\", line 42, in wrapped_app","timestamp":"2026-08-20T11:08:45.346290989Z","level":"error"}
{"message":"    await app(scope, receive, sender)","level":"error","timestamp":"2026-08-20T11:08:45.346295649Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 144, in app","level":"error","timestamp":"2026-08-20T11:08:45.346300211Z"}
{"level":"error","timestamp":"2026-08-20T11:08:45.346304645Z","message":"    response = await f(request)"}
{"message":"               ^^^^^^^^^^^^^^^^","level":"error","timestamp":"2026-08-20T11:08:45.346309007Z"}
{"timestamp":"2026-08-20T11:08:45.346313824Z","level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 706, in app"}
{"level":"error","timestamp":"2026-08-20T11:08:45.346317984Z","message":"    raw_response = await run_endpoint_function("}
{"level":"error","message":"                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.346322482Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/fastapi/routing.py\", line 354, in run_endpoint_function","timestamp":"2026-08-20T11:08:45.346326631Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.346331033Z","level":"error","message":"    return await run_in_threadpool(dependant.call, **values)"}
{"message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.346335253Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/starlette/concurrency.py\", line 34, in run_in_threadpool","level":"error","timestamp":"2026-08-20T11:08:45.346340219Z"}
{"level":"error","timestamp":"2026-08-20T11:08:45.346344511Z","message":"    return await anyio.to_thread.run_sync(func)"}
{"level":"error","message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.346348666Z"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/to_thread.py\", line 65, in run_sync","timestamp":"2026-08-20T11:08:45.347375393Z"}
{"message":"    return await get_async_backend().run_sync_in_worker_thread(","level":"error","timestamp":"2026-08-20T11:08:45.347391477Z"}
{"message":"           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^","timestamp":"2026-08-20T11:08:45.347399417Z","level":"error"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/_backends/_asyncio.py\", line 2641, in run_sync_in_worker_thread","timestamp":"2026-08-20T11:08:45.347406633Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.347414485Z","message":"    return await future","level":"error"}
{"timestamp":"2026-08-20T11:08:45.347422025Z","message":"           ^^^^^^^^^^^^","level":"error"}
{"level":"error","message":"  File \"/usr/local/lib/python3.12/site-packages/anyio/_backends/_asyncio.py\", line 1033, in run","timestamp":"2026-08-20T11:08:45.347429356Z"}
{"timestamp":"2026-08-20T11:08:45.347436701Z","message":"    result = context.run(func, *args)","level":"error"}
{"message":"             ^^^^^^^^^^^^^^^^^^^^^^^^","level":"error","timestamp":"2026-08-20T11:08:45.347451693Z"}
{"message":"  File \"/usr/local/lib/python3.12/site-packages/verigence_security/api/routes/access.py\", line 169, in credential_login","timestamp":"2026-08-20T11:08:45.347460426Z","level":"error"}
{"timestamp":"2026-08-20T11:08:45.347467663Z","level":"error","message":"    raise RuntimeError(\"Configured Security human access-token lifetime is unavailable\")"}
{"message":"RuntimeError: Configured Security human access-token lifetime is unavailable","level":"error","timestamp":"2026-08-20T11:08:45.347474879Z"}
```
