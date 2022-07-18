import multiprocessing
import dashboard

# app_host, app_port = dashboard.get_host_bind()
app_host, app_port = ("0.0.0.0", "80")

worker_class = "gthread"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 4
bind = f"{app_host}:{app_port}"
daemon = True
pidfile = "./gunicorn.pid"
