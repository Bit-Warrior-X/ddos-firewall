# setup.py
"""Setup script for compiling Python modules to .so files."""
from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext

# List of modules to compile to .so
extensions = [
    Extension("core.database", ["core/database.py"]),
    Extension("core.api_client", ["core/api_client.py"]),
    Extension("core.firewall", ["core/firewall.py"]),
    Extension("core.redis_client", ["core/redis_client.py"]),
    Extension("core.fifo_worker", ["core/fifo_worker.py"]),
    Extension("core.temporary_blacklist_monitor", ["core/temporary_blacklist_monitor.py"]),
    Extension("core.initializer", ["core/initializer.py"]),
    Extension("core.app_factory", ["core/app_factory.py"]),
    Extension("utils.auth", ["utils/auth.py"]),
    Extension("utils.validators", ["utils/validators.py"]),
    Extension("routes.l4_routes", ["routes/l4_routes.py"]),
    Extension("routes.l7_routes", ["routes/l7_routes.py"]),
    Extension("routes.common_routes", ["routes/common_routes.py"]),
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

