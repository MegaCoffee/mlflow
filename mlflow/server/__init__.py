import json
import os
import shlex
import sys
import textwrap
import logging
import requests
from flask import Flask, send_from_directory, Response, redirect, request, session, make_response
from flask_oidc import OpenIDConnect
from flask_cors import CORS
from mlflow.server import handlers
from mlflow.server.handlers import (
    get_artifact_handler,
    STATIC_PREFIX_ENV_VAR,
    _add_static_prefix,
    get_model_version_artifact_handler,
)
from mlflow.utils.env import get_env
from mlflow.utils.process import _exec_cmd

# NB: These are internal environment variables used for communication between
# the cli and the forked gunicorn processes.
BACKEND_STORE_URI_ENV_VAR = "_MLFLOW_SERVER_FILE_STORE"
ARTIFACT_ROOT_ENV_VAR = "_MLFLOW_SERVER_ARTIFACT_ROOT"
ARTIFACTS_DESTINATION_ENV_VAR = "_MLFLOW_SERVER_ARTIFACT_DESTINATION"
PROMETHEUS_EXPORTER_ENV_VAR = "prometheus_multiproc_dir"
SERVE_ARTIFACTS_ENV_VAR = "_MLFLOW_SERVER_SERVE_ARTIFACTS"
ARTIFACTS_ONLY_ENV_VAR = "_MLFLOW_SERVER_ARTIFACTS_ONLY"

REL_STATIC_DIR = "js/build"

# 日志系统配置
handler = logging.FileHandler('app.log', encoding='UTF-8')
#设置日志文件，和字符编码
logging_format = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')
handler.setFormatter(logging_format)

#设置日志存储格式，也可以自定义日志格式满足不同的业务需求


app = Flask(__name__, static_folder=REL_STATIC_DIR)
# r'/*' 是通配符，让本服务器所有的 URL 都允许跨域请求
CORS(app, resources=r'/*')
app.config.update({
    'SECRET_KEY': 'my_secret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': '/usr/local/lib/python3.7/site-packages/mlflow/server/client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'mega-mesh',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token'
})
app.logger.addHandler(handler)
oidc = OpenIDConnect(app)


STATIC_DIR = os.path.join(app.root_path, REL_STATIC_DIR)


for http_path, handler, methods in handlers.get_endpoints():
    app.add_url_rule(http_path, handler.__name__, handler, methods=methods)

if os.getenv(PROMETHEUS_EXPORTER_ENV_VAR):
    from mlflow.server.prometheus_exporter import activate_prometheus_exporter

    prometheus_metrics_path = os.getenv(PROMETHEUS_EXPORTER_ENV_VAR)
    if not os.path.exists(prometheus_metrics_path):
        os.makedirs(prometheus_metrics_path)
    activate_prometheus_exporter(app)


# Provide a health check endpoint to ensure the application is responsive
@app.route("/health")
@oidc.require_login
def health():
    return "OK", 200


# Serve the "get-artifact" route.
@app.route(_add_static_prefix("/get-artifact"))
@oidc.require_login
def serve_artifacts():
    return get_artifact_handler()


# Serve the "model-versions/get-artifact" route.
@app.route(_add_static_prefix("/model-versions/get-artifact"))
@oidc.require_login
def serve_model_version_artifact():
    return get_model_version_artifact_handler()


# We expect the react app to be built assuming it is hosted at /static-files, so that requests for
# CSS/JS resources will be made to e.g. /static-files/main.css and we can handle them here.
@app.route(_add_static_prefix("/static-files/<path:path>"))
def serve_static_file(path):
    return send_from_directory(STATIC_DIR, path)

def get_keycloak_token():
    path = "auth/realms/master/protocol/openid-connect/token"
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    data = {
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": get_env('KEYCLOAK_MASTER_USERNAME'),
        "password": get_env('KEYCLOAK_MASTER_PASSWORD')
    }
    r = requests.post(url=url, data=data)
    # print(r)
    if 200 == r.status_code:
        return "bearer {}".format(json.loads(r.content.decode())["access_token"])
    else:
        raise ValueError(r.reason)


def get_user(token, username):
    path = "auth/admin/realms/{}/users".format(get_env('KEYCLOAK_REALM'))
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    url += "?username=" + username
    headers = {"authorization": token}
    r = requests.get(url=url,headers=headers)
    if str(r.status_code).startswith("20"):
        logging.info("get_user: {}".format(r.content))
        if r.content != '' and r.content.decode() != '[]':
            return json.loads(r.content.decode())[0]["id"]
        else:
            app.logger.error("get_user: {}".format(r.content))
            return ""
    else:
        raise ValueError("{}__{}__{}".format(r.status_code, r.reason, r.content))


def logout_keycloak(token, user_id):
    path = "auth/admin/realms/{}/users/{}/logout".format(get_env('KEYCLOAK_REALM'), user_id)
    url = "{}/{}".format(get_env('KEYCLOAK_HOST'), path)
    headers = {"authorization": token}
    r = requests.post(url=url, headers=headers)
    if str(r.status_code).startswith("20"):
        app.logger.info("logout success".format(r.content))
    else:
        raise ValueError("{}__{}__{}".format(r.status_code, r.reason, r.content))

def logout_keycloak_handler():
    mlflow_token = oidc._get_cookie_id_token()
    app.logger.info("====cookie_id_token:{}=====".format(mlflow_token))
    # if not request_token:
    #     return
    # request_token = request_token.replace("")


    token = get_keycloak_token()
    app.logger.info("================ get keycloak token success ===============")
    user_name = mlflow_token["preferred_username"]
    app.logger.info("================ get keycloak username: {} ===============".format(user_name))
    user_id = get_user(token, user_name)
    app.logger.info("================ get keycloak userid: {} ===============".format(user_id))
    if user_id:
        logout_keycloak(token, user_id)


@app.route("/logout")
@oidc.require_login
def logout():
    # logout keycloak
    app.logger.info("================ start logout keycloak ===============")
    # Response.delete_cookie(key='session')
    logout_keycloak_handler()
    # oidc.logout()
    resp = redirect('/')

    resp.delete_cookie("session")
    resp.delete_cookie("oidc_id_token")
    app.logger.info("====clear cookies====")
    return resp


@app.route(_add_static_prefix("/login"))
def login():
    if os.path.exists(os.path.join(STATIC_DIR, "login.html")):
        return send_from_directory(STATIC_DIR, "login.html")


# Serve the index.html for the React App for all other routes.
@app.route(_add_static_prefix("/"))
@oidc.require_login
def serve():
    if os.path.exists(os.path.join(STATIC_DIR, "index.html")):
        return send_from_directory(STATIC_DIR, "index.html")

    text = textwrap.dedent(
        """
    Unable to display MLflow UI - landing page (index.html) not found.

    You are very likely running the MLflow server using a source installation of the Python MLflow
    package.

    If you are a developer making MLflow source code changes and intentionally running a source
    installation of MLflow, you can view the UI by running the Javascript dev server:
    https://github.com/mlflow/mlflow/blob/master/CONTRIBUTING.rst#running-the-javascript-dev-server

    Otherwise, uninstall MLflow via 'pip uninstall mlflow', reinstall an official MLflow release
    from PyPI via 'pip install mlflow', and rerun the MLflow server.
    """
    )
    return Response(text, mimetype="text/plain")


def _build_waitress_command(waitress_opts, host, port):
    opts = shlex.split(waitress_opts) if waitress_opts else []
    return (
        ["waitress-serve"]
        + opts
        + ["--host=%s" % host, "--port=%s" % port, "--ident=mlflow", "mlflow.server:app"]
    )


def _build_gunicorn_command(gunicorn_opts, host, port, workers):
    bind_address = "%s:%s" % (host, port)
    opts = shlex.split(gunicorn_opts) if gunicorn_opts else []
    return ["gunicorn"] + opts + ["-b", bind_address, "-w", "%s" % workers, "mlflow.server:app"]


def _run_server(
    file_store_path,
    default_artifact_root,
    serve_artifacts,
    artifacts_only,
    artifacts_destination,
    host,
    port,
    static_prefix=None,
    workers=None,
    gunicorn_opts=None,
    waitress_opts=None,
    expose_prometheus=None,
):
    """
    Run the MLflow server, wrapping it in gunicorn or waitress on windows
    :param static_prefix: If set, the index.html asset will be served from the path static_prefix.
                          If left None, the index.html asset will be served from the root path.
    :return: None
    """
    env_map = {}
    if file_store_path:
        env_map[BACKEND_STORE_URI_ENV_VAR] = file_store_path
    if default_artifact_root:
        env_map[ARTIFACT_ROOT_ENV_VAR] = default_artifact_root
    if serve_artifacts:
        env_map[SERVE_ARTIFACTS_ENV_VAR] = "true"
    if artifacts_only:
        env_map[ARTIFACTS_ONLY_ENV_VAR] = "true"
    if artifacts_destination:
        env_map[ARTIFACTS_DESTINATION_ENV_VAR] = artifacts_destination
    if static_prefix:
        env_map[STATIC_PREFIX_ENV_VAR] = static_prefix

    if expose_prometheus:
        env_map[PROMETHEUS_EXPORTER_ENV_VAR] = expose_prometheus

    # TODO: eventually may want waitress on non-win32
    if sys.platform == "win32":
        full_command = _build_waitress_command(waitress_opts, host, port)
    else:
        full_command = _build_gunicorn_command(gunicorn_opts, host, port, workers or 4)
    _exec_cmd(full_command, extra_env=env_map, capture_output=False)
