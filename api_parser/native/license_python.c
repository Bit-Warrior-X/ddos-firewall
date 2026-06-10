#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <ebpf_firewall_utils.h>

static PyObject* py_get_license_status(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    int ret = get_license_status();
    return PyLong_FromLong((long)ret);
}

static PyObject* py_get_license_info(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;

    license_info_t info;
    int ret = get_license_info(&info);

    return Py_BuildValue(
        "{s:i,s:i,s:s,s:L}",
        "status", ret,
        "feature", info.feature,
        "license_type", info.license_type,
        "days_left", info.days_left
    );
}

static PyMethodDef LicenseMethods[] = {
    {"get_license_status", py_get_license_status, METH_NOARGS,
     "Validate license file and return status code (0=ok, <0=error)."},
    {"get_license_info", py_get_license_info, METH_NOARGS,
     "Validate license and return status, feature, license_type, days_left."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef license_module = {
    PyModuleDef_HEAD_INIT,
    "_license_native",
    "Native license validation via ebpf_firewall_utils.",
    -1,
    LicenseMethods
};

PyMODINIT_FUNC PyInit__license_native(void)
{
    return PyModule_Create(&license_module);
}
