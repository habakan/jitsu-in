#include <node_api.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "wasm_export.h"

typedef struct {
    wasm_module_inst_t module;
    wasm_exec_env_t env;
} instance_t;

static int runtime_ready;

static napi_value fail(napi_env env, const char *message) {
    napi_throw_error(env, NULL, message);
    return NULL;
}

static instance_t *get_instance(napi_env env, napi_value value) {
    instance_t *instance = NULL;
    if (napi_get_value_external(env, value, (void **)&instance) != napi_ok) return NULL;
    return instance;
}

static void finalize_instance(napi_env env, void *data, void *hint) {
    instance_t *instance = data;
    if (!instance) return;
    wasm_runtime_destroy_exec_env(instance->env);
    wasm_runtime_deinstantiate(instance->module);
    free(instance);
}

static wasm_module_t get_module(napi_env env, napi_value value) {
    wasm_module_t module = NULL;
    if (napi_get_value_external(env, value, (void **)&module) != napi_ok) return NULL;
    return module;
}

/* Modules are never unloaded: WAMR keeps pointers into the bytes, and a test process is short-lived */
static napi_value load_module(napi_env env, napi_callback_info info) {
    napi_value args[1], result;
    size_t argc = 1, length = 0;
    void *source = NULL;
    uint8_t *bytes;
    char error[256] = {0};
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_buffer_info(env, args[0], &source, &length) != napi_ok)
        return fail(env, "loadModule expects a Buffer");
    if (!runtime_ready) {
        RuntimeInitArgs init_args = {0};
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
        if (!wasm_runtime_full_init(&init_args)) return fail(env, "WAMR initialization failed");
        runtime_ready = 1;
        wasm_runtime_set_default_running_mode(Mode_Interp);
    }
    if (!(bytes = malloc(length))) return fail(env, "WAMR module buffer allocation failed");
    memcpy(bytes, source, length);
    wasm_module_t module = wasm_runtime_load(bytes, (uint32_t)length, error, sizeof(error));
    if (!module) return fail(env, error[0] ? error : "WAMR could not load the module");
    napi_create_external(env, module, NULL, NULL, &result);
    return result;
}

static napi_value instantiate(napi_env env, napi_callback_info info) {
    napi_value args[1];
    size_t argc = 1;
    char error[256] = {0};
    wasm_module_t wasm_module;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        !(wasm_module = get_module(env, args[0])))
        return fail(env, "instantiate expects a module from loadModule");
    instance_t *instance = calloc(1, sizeof(*instance));
    if (!instance) return fail(env, "WAMR instance allocation failed");
    instance->module = wasm_runtime_instantiate(wasm_module, 16384, 0, error, sizeof(error));
    if (!instance->module) {
        free(instance);
        return fail(env, error[0] ? error : "WAMR instantiation failed");
    }
    instance->env = wasm_runtime_create_exec_env(instance->module, 16384);
    if (!instance->env) {
        wasm_runtime_deinstantiate(instance->module);
        free(instance);
        return fail(env, "WAMR execution environment creation failed");
    }
    napi_value result;
    napi_create_external(env, instance, finalize_instance, NULL, &result);
    return result;
}

static napi_value call_export(napi_env env, napi_callback_info info) {
    napi_value args[3];
    size_t argc = 3, name_len = 0;
    uint32_t arg_count = 0;
    char name[128];
    bool ok;
    instance_t *instance;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 3 ||
        !(instance = get_instance(env, args[0])) ||
        napi_get_value_string_utf8(env, args[1], name, sizeof(name), &name_len) != napi_ok ||
        napi_get_array_length(env, args[2], &arg_count) != napi_ok || arg_count > 16)
        return fail(env, "call expects an instance, export name, and up to 16 i32 arguments");
    wasm_function_inst_t function = wasm_runtime_lookup_function(instance->module, name);
    if (!function) return fail(env, "WAMR export not found");
    uint32_t argv[17] = {0};
    for (uint32_t i = 0; i < arg_count; i++) {
        napi_value value;
        int32_t argument;
        napi_get_element(env, args[2], i, &value);
        if (napi_get_value_int32(env, value, &argument) != napi_ok)
            return fail(env, "WAMR arguments must be i32 values");
        argv[i] = (uint32_t)argument;
    }
    ok = wasm_runtime_call_wasm(instance->env, function, (uint32_t)arg_count, argv);
    if (!ok) {
        const char *exception = wasm_runtime_get_exception(instance->module);
        return fail(env, exception ? exception : "WAMR export call failed");
    }
    napi_value result;
    napi_create_int32(env, (int32_t)argv[0], &result);
    return result;
}

static napi_value has_export(napi_env env, napi_callback_info info) {
    napi_value args[2], result;
    size_t argc = 2, length = 0;
    char name[128];
    instance_t *instance;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 ||
        !(instance = get_instance(env, args[0])) ||
        napi_get_value_string_utf8(env, args[1], name, sizeof(name), &length) != napi_ok)
        return fail(env, "hasExport expects an instance and export name");
    napi_get_boolean(env, wasm_runtime_lookup_function(instance->module, name) != NULL, &result);
    return result;
}

static napi_value import_count(napi_env env, napi_callback_info info) {
    napi_value args[1], result;
    size_t argc = 1;
    wasm_module_t module;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        !(module = get_module(env, args[0])))
        return fail(env, "importCount expects a module");
    napi_create_uint32(env, wasm_runtime_get_import_count(module), &result);
    return result;
}

/* [{ name, kind }] with kind "function", "memory" or "other" */
static napi_value exports_of(napi_env env, napi_callback_info info) {
    napi_value args[1], result;
    size_t argc = 1;
    wasm_module_t module;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        !(module = get_module(env, args[0])))
        return fail(env, "exports expects a module");
    int32_t n = wasm_runtime_get_export_count(module);
    napi_create_array_with_length(env, (size_t)n, &result);
    for (int32_t i = 0; i < n; i++) {
        wasm_export_t e;
        napi_value item, name, kind;
        wasm_runtime_get_export_type(module, i, &e);
        napi_create_object(env, &item);
        napi_create_string_utf8(env, e.name, NAPI_AUTO_LENGTH, &name);
        napi_create_string_utf8(env,
                                e.kind == WASM_IMPORT_EXPORT_KIND_FUNC     ? "function"
                                : e.kind == WASM_IMPORT_EXPORT_KIND_MEMORY ? "memory"
                                                                           : "other",
                                NAPI_AUTO_LENGTH, &kind);
        napi_set_named_property(env, item, "name", name);
        napi_set_named_property(env, item, "kind", kind);
        napi_set_element(env, result, (uint32_t)i, item);
    }
    return result;
}

/* The instance's linear memory as an ArrayBuffer. Valid because neither module can grow its memory */
static napi_value memory_of(napi_env env, napi_callback_info info) {
    napi_value args[1], result;
    size_t argc = 1;
    instance_t *instance;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        !(instance = get_instance(env, args[0])))
        return fail(env, "memory expects an instance");
    wasm_memory_inst_t memory = wasm_runtime_get_default_memory(instance->module);
    if (!memory) return fail(env, "WAMR instance has no memory");
    size_t length = (size_t)wasm_memory_get_cur_page_count(memory) * wasm_memory_get_bytes_per_page(memory);
    if (napi_create_external_arraybuffer(env, wasm_memory_get_base_address(memory), length, NULL, NULL, &result) !=
        napi_ok)
        return fail(env, "this Node does not allow external ArrayBuffers");
    return result;
}

static napi_value read_memory(napi_env env, napi_callback_info info) {
    napi_value args[3], result;
    size_t argc = 3;
    uint32_t offset, length;
    instance_t *instance;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 3 ||
        !(instance = get_instance(env, args[0])) || napi_get_value_uint32(env, args[1], &offset) != napi_ok ||
        napi_get_value_uint32(env, args[2], &length) != napi_ok)
        return fail(env, "read expects an instance, offset, and length");
    if (!wasm_runtime_validate_app_addr(instance->module, offset, length))
        return fail(env, "WAMR memory range is invalid");
    void *source = wasm_runtime_addr_app_to_native(instance->module, offset);
    if (!source) return fail(env, "WAMR memory offset is invalid");
    void *copy;
    napi_create_buffer_copy(env, length, source, &copy, &result);
    return result;
}

static napi_value write_memory(napi_env env, napi_callback_info info) {
    napi_value args[3], result;
    size_t argc = 3, length = 0;
    uint32_t offset;
    void *source = NULL;
    instance_t *instance;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 3 ||
        !(instance = get_instance(env, args[0])) || napi_get_value_uint32(env, args[1], &offset) != napi_ok ||
        napi_get_buffer_info(env, args[2], &source, &length) != napi_ok)
        return fail(env, "write expects an instance, offset, and Buffer");
    if (!wasm_runtime_validate_app_addr(instance->module, offset, (uint32_t)length))
        return fail(env, "WAMR memory range is invalid");
    void *destination = wasm_runtime_addr_app_to_native(instance->module, offset);
    if (!destination) return fail(env, "WAMR memory offset is invalid");
    memcpy(destination, source, length);
    napi_get_undefined(env, &result);
    return result;
}

static napi_value init(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        {"loadModule", NULL, load_module, NULL, NULL, NULL, napi_default, NULL},
        {"instantiate", NULL, instantiate, NULL, NULL, NULL, napi_default, NULL},
        {"call", NULL, call_export, NULL, NULL, NULL, napi_default, NULL},
        {"hasExport", NULL, has_export, NULL, NULL, NULL, napi_default, NULL},
        {"importCount", NULL, import_count, NULL, NULL, NULL, napi_default, NULL},
        {"exports", NULL, exports_of, NULL, NULL, NULL, napi_default, NULL},
        {"memory", NULL, memory_of, NULL, NULL, NULL, napi_default, NULL},
        {"read", NULL, read_memory, NULL, NULL, NULL, napi_default, NULL},
        {"write", NULL, write_memory, NULL, NULL, NULL, napi_default, NULL},
    };
    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
