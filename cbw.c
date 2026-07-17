#include "cbw.h"

/*
 * Created by coop on 7/14/26
 * 
 * Password manager that uses RBW for creating passwords.
 * All passwords will be encrypted and managed locally
 * usage: cbw gen 5 -u HappyFeather -l feathers.com
 *        cbw gen <length> -u <username> -l <url>
*/

/*Global variables*/
static Vault vault = {0};

// ====================== PATH & HELPERS ======================
static char *expand_path(const char *rel) {
    static char buf[1024];
    const char *home = getenv("HOME");
    snprintf(buf, sizeof(buf), "%s%s", home, rel + 1);  // skip ~
    return buf;
}

static int derive_key(const char *pw, const unsigned char *salt, unsigned char *key) {
    if (sodium_init() < 0) return -1;
    return crypto_pwhash(key, KEY_LEN, pw, strlen(pw),
                         salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

static void copy_to_clipboard(const char *text) {
    if (!text || strlen(text) == 0) return;

    // Try Wayland first (common on modern KDE)
    if (system("wl-copy --version > /dev/null 2>&1") == 0) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "echo -n '%s' | wl-copy > /dev/null 2>&1", text);
        if (system(cmd) == 0) return;
    }

    // Fall back to X11
    if (system("xclip -version > /dev/null 2>&1") == 0) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "echo -n '%s' | xclip -selection clipboard > /dev/null 2>&1", text);
        if (system(cmd) == 0) return;
    }
}

// ====================== JSON SERIALIZATION ======================
static cJSON *entries_to_json(const Entry *entries, size_t count) {
    cJSON *root = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "label", entries[i].label);
        cJSON_AddStringToObject(obj, "username", entries[i].username);
        cJSON_AddStringToObject(obj, "password", entries[i].password);
        cJSON_AddItemToArray(root, obj);
    }
    return root;
}

static Entry *json_to_entries(cJSON *root, size_t *out_count) {
    if (!cJSON_IsArray(root)) return NULL;
    size_t count = cJSON_GetArraySize(root);
    Entry *entries = calloc(count, sizeof(Entry));
    if (!entries) return NULL;

    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        strncpy(entries[i].label, cJSON_GetStringValue(cJSON_GetObjectItem(item, "label")), 127);
        strncpy(entries[i].username, cJSON_GetStringValue(cJSON_GetObjectItem(item, "username")), 127);
        strncpy(entries[i].password, cJSON_GetStringValue(cJSON_GetObjectItem(item, "password")), 255);
    }
    *out_count = count;
    return entries;
}

// ====================== ENCRYPT / DECRYPT CORE ======================
static int load_salt(void) {
    char *path = expand_path(VAULT_PATH);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char magic[8];
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, MAGIC, 8) != 0) {
        fclose(f);
        return -1;
    }
    fread(vault.salt, 1, SALT_LEN, f);
    fclose(f);
    return 0;
}

static int save_vault(Entry *entries, size_t count) {
    cJSON *json = entries_to_json(entries, count);
    if (!json) return -1;
    char *json_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!json_str) return -1;

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, NONCE_LEN);

    size_t ct_len = strlen(json_str) + MAC_LEN;
    unsigned char *ct = malloc(ct_len);
    if (!ct) { free(json_str); return -1; }

    unsigned long long written;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &written,
            (const unsigned char*)json_str, strlen(json_str),
            NULL, 0, NULL, nonce, vault.key) != 0) {
        free(ct); free(json_str); return -1;
    }
    free(json_str);

    char *path = expand_path(VAULT_PATH);
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);   // warning fixed by larger buffer if needed

    FILE *f = fopen(tmp, "wb");
    if (!f) { free(ct); return -1; }

    fwrite(MAGIC, 1, MAGIC_LEN, f);
    fwrite(vault.salt, 1, SALT_LEN, f);
    fwrite(nonce, 1, NONCE_LEN, f);
    fwrite(ct, 1, written, f);
    fclose(f);

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        free(ct);
        return -1;
    }
    chmod(path, 0600);
    free(ct);
    return 0;
}

static Entry *load_vault(size_t *out_count) {
    *out_count = 0;
    char *path = expand_path(VAULT_PATH);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    

    char magic_buf[MAGIC_LEN];
    if (fread(magic_buf, 1, MAGIC_LEN, f) != MAGIC_LEN || memcmp(magic_buf, MAGIC, MAGIC_LEN) != 0) {
        fclose(f); return NULL;
    }

    fread(vault.salt, 1, SALT_LEN, f);

    unsigned char nonce[NONCE_LEN];
    if (fread(nonce, 1, NONCE_LEN, f) != NONCE_LEN) {
        fclose(f); return NULL;
    }

    long header_size = MAGIC_LEN + SALT_LEN + NONCE_LEN;
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    long ct_size = file_size - header_size;
    if (ct_size <= 0) {
        fclose(f);
        return NULL;
    }
    fseek(f, header_size, SEEK_SET);

    unsigned char *ct = malloc(ct_size);
    if (!ct || fread(ct, 1, ct_size, f) != (size_t)ct_size) {
        free(ct); fclose(f); return NULL;
    }
    fclose(f);

    unsigned char *pt = malloc(ct_size + 1);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &pt_len, NULL,
            ct, ct_size, NULL, 0, nonce, vault.key) != 0) {
        free(ct); free(pt); return NULL;
    }
    free(ct);
    pt[pt_len] = '\0';

    cJSON *json = cJSON_Parse((char *)pt);
    free(pt);
    if (!json) return NULL;
    

    Entry *entries = json_to_entries(json, out_count);
    cJSON_Delete(json);

    return entries;
}

// ====================== UNLOCK ======================
static int unlock_vault(void) {
    if (vault.unlocked) return 0;

    // Load salt first if vault exists
    if (load_salt() != 0) {
        fprintf(stderr, "No vault found. Run 'cbw init' first.\n");
        return -1;
    }

    char pw[128] = {0};
    printf("Enter master password: ");
    fgets(pw, sizeof(pw), stdin);
    pw[strcspn(pw, "\n")] = 0;

    if (derive_key(pw, vault.salt, vault.key) != 0) {
        sodium_memzero(pw, sizeof(pw));
        return -1;
    }
    sodium_memzero(pw, sizeof(pw));
    vault.unlocked = 1;
    return 0;
}

// ====================== COMMAND TABLE ======================
int cmd_help(int argc, char **argv) { (void)argc; (void)argv; print_usage(); return 0; }
int cmd_version(int argc, char **argv) { (void)argc; (void)argv; print_version(); return 0; }

int cmd_init(int argc, char **argv)
{
    (void)argc; (void)argv;
    char *dir = expand_path(VAULT_DIR);
    mkdir(dir, 0700);

    char pw[128], confirm[128];
    printf("Enter master password: "); fgets(pw, sizeof(pw), stdin); pw[strcspn(pw,"\n")]=0;
    printf("Confirm: "); fgets(confirm, sizeof(confirm), stdin); confirm[strcspn(confirm,"\n")]=0;

    if (strcmp(pw, confirm) != 0) {
        fprintf(stderr, "Mismatch\n");
        sodium_memzero(pw, sizeof(pw));
        return 1;
    }

    derive_key(pw, vault.salt, vault.key);  // salt generated inside
    sodium_memzero(pw, sizeof(pw));

    save_vault(NULL, 0);  // empty vault
    vault.unlocked = 1;
    printf("Vault initialized at %s\n", expand_path(VAULT_DIR "/" VAULT_FILE));
    return 0;
}

int cmd_gen(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s gen <words> [-u username] [-l label]\n", PROGRAM_NAME);
        return 1;
    }

    int words = atoi(argv[1]);           // "5" in your example → 5-word passphrase
    if (words <= 0) words = 4;           // sensible default

    char username[128] = {0};
    char label[128] = {0};

    // Parse -u and -l (simple getopt on remaining args)
    static struct option long_opts[] = {
        {"username", required_argument, 0, 'u'},
        {"label",    required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    optind = 2; // skip "gen" and the number
    int opt;
    while ((opt = getopt_long(argc, argv, "u:l:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'u': strncpy(username, optarg, sizeof(username)-1); break;
            case 'l': strncpy(label,    optarg, sizeof(label)-1);    break;
        }
    }

    if (label[0] == 0) {
        fprintf(stderr, "Error: label (-l) is required\n");
        return 1;
    }

    // === Generate password using rbw ===
    char cmd[256];
    snprintf(cmd, sizeof(cmd), RBW_PATH " " GEN " %d", words);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen rbw generate");
        return 1;
    }

    char generated[256] = {0};
    if (!fgets(generated, sizeof(generated), fp)) {
        fprintf(stderr, "Failed to read password from rbw\n");
        pclose(fp);
        return 1;
    }
    pclose(fp);

    // Trim newline
    generated[strcspn(generated, "\n")] = 0;

    printf("Generated %d-word passphrase for label '%s'\n", words, label);

    if (unlock_vault() != 0) 
    {
        fprintf(stderr, "Failed to unlock vault.\n");
        sodium_memzero(generated, sizeof(generated));
        return 1;
    }

    size_t count = 0;
    Entry *entries = load_vault(&count);

    if (!entries) {
        entries = malloc(sizeof(Entry));
        count = 0;
    }

    // Resize array
    entries = realloc(entries, (count + 1) * sizeof(Entry));
    if (!entries) {
        fprintf(stderr, "Memory allocation failed\n");
        sodium_memzero(generated, sizeof(generated));
        return 1;
    }
    Entry *new_e = &entries[count];
    strncpy(new_e->label, label, sizeof(new_e->label) - 1);
    new_e->label[sizeof(new_e->label)-1] = '\0';

    strncpy(new_e->username, username, sizeof(new_e->username) - 1);
    new_e->username[sizeof(new_e->username)-1] = '\0';

    strncpy(new_e->password, generated, sizeof(new_e->password) - 1);
    new_e->password[sizeof(new_e->password)-1] = '\0';

    if (save_vault(entries, count + 1) == 0) {
        printf("Saved entry for %s\n", label);
        copy_to_clipboard(generated);
    } else {
        fprintf(stderr, "Failed to save vault\n");
    }
    free(entries);

    // Security: wipe sensitive memory
    sodium_memzero(generated, sizeof(generated));
    return 0;
}

int cmd_get(int argc, char **argv)
{
    int clip = 0;
    char label[128] = {0};

    // Simple option parsing for -c / --clip
    if (argc >= 2) {
        if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--clip") == 0) {
            clip = 1;
            if (argc >= 3) strncpy(label, argv[2], sizeof(label)-1);
        } else {
            strncpy(label, argv[1], sizeof(label)-1);
        }
    }

    if (label[0] == 0) {
        fprintf(stderr, "Usage: %s get [-c|--clip] <label>\n", PROGRAM_NAME);
        return 1;
    }

    if (unlock_vault() != 0) return 1;

    size_t count = 0;
    Entry *entries = load_vault(&count);
    if (!entries || count == 0) {
        fprintf(stderr, "No entries found or vault empty.\n");
        free(entries);
        return 1;
    }
    
    for (size_t i = 0; i < count; i++) {
        if (strcmp(entries[i].label, label) == 0) {
            if (clip) {
                copy_to_clipboard(entries[i].password);
            } else {
                printf("Label:    %s\n", entries[i].label);
                printf("Username: %s\n", entries[i].username);
                printf("Password: %s\n", entries[i].password);
            }
            sodium_memzero(entries[i].password, sizeof(entries[i].password));
            free(entries);
            return 0;
        }
    }

    fprintf(stderr, "Entry '%s' not found.\n", label);
    free(entries);
    return 1;
}
int cmd_insert(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s insert <label> <username> <password>\n", PROGRAM_NAME);
        return 1;
    }

    const char *label = argv[1];
    const char *username = argv[2];
    const char *password = argv[3];

    if (unlock_vault() != 0) return 1;

    size_t count = 0;
    Entry *entries = load_vault(&count);
    if (!entries) {
        entries = malloc(sizeof(Entry));
        count = 0;
    }

    // Resize array
    entries = realloc(entries, (count + 1) * sizeof(Entry));
    if (!entries) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    Entry *new_e = &entries[count];
    strncpy(new_e->label, label, sizeof(new_e->label) - 1);
    new_e->label[sizeof(new_e->label)-1] = '\0';

    strncpy(new_e->username, username, sizeof(new_e->username) - 1);
    new_e->username[sizeof(new_e->username)-1] = '\0';

    strncpy(new_e->password, password, sizeof(new_e->password) - 1);
    new_e->password[sizeof(new_e->password)-1] = '\0';

    if (save_vault(entries, count + 1) == 0) {
        printf("Inserted entry for %s\n", label);
    } else {
        fprintf(stderr, "Failed to save vault\n");
    }
    free(entries);

    return 0;
}
int cmd_list(int argc, char **argv)
{
    (void)argc; (void)argv;

        if (argc >= 2) {
        fprintf(stderr, "Usage: %s list\n", PROGRAM_NAME);
        return 1;
    }

    if (unlock_vault() != 0) return 1;

    size_t count = 0;
    Entry *entries = load_vault(&count);
    if (!entries || count == 0) {
        printf("No entries in vault.\n");
        free(entries);
        return 0;
    }

    printf("Entries (%zu):\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("  %s  |  %s\n", entries[i].label, entries[i].username);
    }
    free(entries);
    return 0;
}

int cmd_delete(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s delete <label>\n", PROGRAM_NAME);
        return 1;
    }

    if(unlock_vault() != 0) return 1;

    size_t count = 0;
    Entry *entries = load_vault(&count);
    if (!entries || count == 0) {
        printf("No entries in vault.\n");
        free(entries);
        return 0;
    }

    for(int pw_entry = 0; pw_entry < count; pw_entry++) {
        if(strcmp(entries[pw_entry].label, argv[1]) == 0) {
            // Shift remaining entries down
            for(int j = pw_entry; j < count - 1; j++) {
                entries[j] = entries[j + 1];
            }
            count--;
            if(save_vault(entries, count) == 0) {
                printf("Deleted entry '%s'\n", argv[1]);
            } else {
                fprintf(stderr, "Failed to save vault after deletion\n");
            }
            free(entries);
            return 0;
        }
    }
    printf("Entry '%s' not found\n", argv[1]);
    free(entries);
    return 0;
}

// ====================== Encrypt ======================

unsigned char* encryptKey(const char *password, const unsigned char *key)
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char derived[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived, sizeof(derived), password, strlen(password),
                        salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Failed to derive key from password\n");
        return NULL;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char* ciphertext = malloc(strlen((const char*)key) + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext, key, strlen((const char*)key), nonce, derived);
    
    unsigned char* result = malloc(sizeof(salt) + sizeof(nonce) + strlen((const char*)key) + crypto_secretbox_MACBYTES);
    memcpy(result, salt, sizeof(salt));
    memcpy(result + sizeof(salt), nonce, sizeof(nonce));
    memcpy(result + sizeof(salt) + sizeof(nonce), ciphertext, strlen((const char*)key) + crypto_secretbox_MACBYTES);
    
    free(ciphertext);
    return result;

}

unsigned char* decryptKey(const char *password, const unsigned char *encrypted)
{
    const size_t hdr = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;
    if(strlen((const char*)encrypted) < hdr + crypto_secretbox_MACBYTES) {
        fprintf(stderr, "Encrypted data is too short\n");
        return NULL;
    }
    unsigned char salt[crypto_pwhash_SALTBYTES];
    memcpy(salt, encrypted, sizeof(salt));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted + sizeof(salt), sizeof(nonce));

    unsigned char derived[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived, sizeof(derived), password, strlen(password),
                        salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Failed to derive key from password\n");
        return NULL;
    }

    size_t ciphertext_len = strlen((const char*)encrypted) - sizeof(salt) - sizeof(nonce);
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    memcpy(ciphertext, encrypted + sizeof(salt) + sizeof(nonce), ciphertext_len);

    size_t plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
    unsigned char* decrypted = (unsigned char*)malloc(plaintext_len + 1);
    if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, derived) != 0) {
        fprintf(stderr, "Failed to decrypt key\n");
        free(ciphertext);
        free(decrypted);
        return NULL;
    }
    decrypted[plaintext_len] = '\0';

    free(ciphertext);
    return decrypted;
}

// ====================== HELP ======================

void print_usage(void)
{
    printf("Usage: %s <command> [OPTIONS]\n\n", PROGRAM_NAME);
    printf("Commands:\n");
    for (int i = 0; commands[i].name != NULL; i++) {
        printf("  %-10s %s\n", commands[i].name, commands[i].short_desc);
    }
    printf("\nExamples:\n");
    printf("  %s init\n", PROGRAM_NAME);
    printf("  %s gen 5 -u HappyFeather -l feathers.com\n", PROGRAM_NAME);
    printf("  %s get -c feathers.com                      # copy password to clipboard\n", PROGRAM_NAME);
    printf("  %s get helloworld\n", PROGRAM_NAME);
    printf("  %s list\n", PROGRAM_NAME);
}

void print_version(void)
{
    printf("%s version %s\n", PROGRAM_NAME, PROGRAM_VERSION);
}

int main(int argc, char* argv[])
{
    
    if (argc < 2) {
        print_usage();
        return EXIT_FAILURE;
    }

    const char *subcmd = argv[1];

    // Global flags
    if (strcmp(subcmd, "--help") == 0 || strcmp(subcmd, "-h") == 0) {
        print_usage();
        return EXIT_SUCCESS;
    }
    if (strcmp(subcmd, "--version") == 0 || strcmp(subcmd, "-V") == 0) {
        print_version();
        return EXIT_SUCCESS;
    }

    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(subcmd, commands[i].name) == 0) {
            return commands[i].func(argc - 1, argv + 1);
        }
    }

    fprintf(stderr, "%s: unknown command '%s'\n", PROGRAM_NAME, subcmd);
    fprintf(stderr, "Run '%s help' for usage.\n", PROGRAM_NAME);
    return EXIT_SUCCESS;
    
}