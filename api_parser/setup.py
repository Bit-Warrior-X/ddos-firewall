# setup.py
"""Setup script for compiling Python modules to .so files."""
import os

from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
EBPF_DIR = os.path.join(ROOT_DIR, "..", "ebpf_firewall")

# List of modules to compile to .so
extensions = [
    Extension("core.database", ["core/database.py"]),
    Extension("core.api_client", ["core/api_client.py"]),
    Extension("core.firewall", ["core/firewall.py"]),
    Extension("core.redis_client", ["core/redis_client.py"]),
    Extension("core.listening_ports", ["core/listening_ports.py"]),
    Extension("core.fifo_worker", ["core/fifo_worker.py"]),
    Extension("core.temporary_blacklist_monitor", ["core/temporary_blacklist_monitor.py"]),
    Extension("core.license_check", ["core/license_check.py"]),
    Extension("core.license_monitor", ["core/license_monitor.py"]),
    Extension("core.edge_list_sync", ["core/edge_list_sync.py"]),
    Extension("core.athens_cache_stats", ["core/athens_cache_stats.py"]),
    Extension("core.cache_hit_sync", ["core/cache_hit_sync.py"]),
    Extension("core.backend_whitelist", ["core/backend_whitelist.py"]),
    Extension("core.initializer", ["core/initializer.py"]),
    Extension("core.app_factory", ["core/app_factory.py"]),
    Extension("utils.auth", ["utils/auth.py"]),
    Extension("utils.validators", ["utils/validators.py"]),
    Extension("routes.l4_routes", ["routes/l4_routes.py"]),
    Extension("routes.l7_routes", ["routes/l7_routes.py"]),
    Extension("routes.common_routes", ["routes/common_routes.py"]),
    Extension(
        "core._license_native",
        sources=[
            "native/license_python.c",
            os.path.join(EBPF_DIR, "userspace/src/ebpf_firewall_utils.c"),
            "native/license_log_stub.c",
        ],
        include_dirs=[
            os.path.join(EBPF_DIR, "userspace/include"),
            EBPF_DIR,
        ],
        libraries=["crypto"],
        extra_compile_args=[
            "-include",
            os.path.join(EBPF_DIR, "common.h"),
        ],
    ),
]

setup(
    name="api_parser",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'language_level': "3",
            'embedsignature': True,
        },
        build_dir="build"
    ),
    cmdclass={'build_ext': build_ext},
    zip_safe=False,
)

