/* USE_EXTERNAL_DEFAULT_CALLBACKS: stdio/abort を引き込まないため。API の誤用と内部エラーは即停止する */
void secp256k1_default_illegal_callback_fn(const char *msg, void *data) { (void)msg; (void)data; __builtin_trap(); }
void secp256k1_default_error_callback_fn(const char *msg, void *data) { (void)msg; (void)data; __builtin_trap(); }
