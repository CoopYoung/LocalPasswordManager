#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <sodium.h>
#include <getopt.h>
#include "external/cJSON.h"

#define RBW_PATH "/usr/bin/rbw"   /*rust bit warden binary*/
#define GEN "generate"
#define CREATE_PW  4
#define CREATE_USER 3
#define CREATE_URL 5

#define SUCCESS   (1)
#define FAILURE  (2)

#define MAX_CMD_SIZE (255)
#define MAX_CMD_ARGS (10)
#define UNAME_FLAG "-u"
#define URL_FLAG "-l"
#define HELP_FLAG "-h"
 
#define PWD_GEN "gen"
#define MAX_PWD_LEN 100
#define MAX_UNAME_LEN 100

#define PROGRAM_NAME    "cbw"
#define PROGRAM_VERSION "0.1.0"
#define VAULT_PATH      "~/.config/cbw/vault"

#define MAGIC          "CBWVAULT"
#define MAGIC_LEN      8
#define SALT_LEN       crypto_pwhash_SALTBYTES
#define KEY_LEN        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCE_LEN      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define MAC_LEN        crypto_aead_xchacha20poly1305_ietf_ABYTES

#define VAULT_DIR      "~/.config/cbw"
#define VAULT_FILE     "vault"

// ====================== DATA MODEL ======================
typedef struct {
    char label[128];
    char username[128];
    char password[256];   // plaintext only while in memory
    // TODO: add created, notes, etc.
} Entry;

typedef struct {
    unsigned char salt[SALT_LEN];
    unsigned char key[KEY_LEN];
    int unlocked;
} Vault;

// ====================== FORWARD DECLS ======================

int cmd_help(int argc, char **argv);
int cmd_version(int argc, char **argv);
int cmd_init(int argc, char **argv);
int cmd_gen(int argc, char **argv);
int cmd_get(int argc, char **argv);
int cmd_list(int argc, char **argv);
int cmd_delete(int argc, char **argv);
int cmd_insert(int argc, char **argv);

char* encrypt_entry(const Entry *entry, const unsigned char *key, size_t key_len);
char* decrypt_entry(const char *encrypted, const unsigned char *key, size_t key_len);
unsigned char* encryptKey(const char *password, const unsigned char *key);
unsigned char* decryptKey(const char *password, const unsigned char *encrypted);

void print_usage();
void print_version();
// ====================== COMMAND TABLE ======================
struct command {
    const char *name;
    const char *short_desc;
    int (*func)(int argc, char **argv);
};

static const struct command commands[] = {
    {"init",    "Initialize encrypted vault (set master password)", cmd_init},
    {"gen",     "Generate password via rbw and store encrypted",    cmd_gen},
    {"get",     "Retrieve and reveal a password",                   cmd_get},
    {"insert",  "Insert a new entry into the vault",                cmd_insert},
    {"list",    "List all entries (labels + usernames)",            cmd_list},
    {"delete",  "Delete an entry",                                  cmd_delete},
    {"help",    "Show this help",                                   cmd_help},
    {"version", "Show version",                                     cmd_version},
    {NULL, NULL, NULL}
};

