/* USE_EXTERNAL_DEFAULT_CALLBACKS, so libsecp256k1 does not drag in stdio or abort. Misuse of the API
 * and internal errors stop the program immediately */
void secp256k1_default_illegal_callback_fn(const char *msg, void *data) { (void)msg; (void)data; __builtin_trap(); }
void secp256k1_default_error_callback_fn(const char *msg, void *data) { (void)msg; (void)data; __builtin_trap(); }
