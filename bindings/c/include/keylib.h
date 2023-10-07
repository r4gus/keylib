#include <stdint.h>
#include <stdlib.h>

typedef enum{
    SUCCESS = 0,
    DoesAlreadyExist = -1,
    DoesNotExist = -2,
    KeyStoreFull = -3,
    OutOfMemory = -4,
    Timeout = -5,
    Other = -6,
} Error;

typedef enum{
    Denied = 0,
    Accepted = 1,
} UpResult;

typedef struct{
    char* payload;
    size_t len;
} Data;

typedef struct{
    int (*up)(const char* info, const char* user, const char* rp);
    int (*uv)(const char* info, const char* user, const char* rp);
    int (*select)(const char* rpId, char** users);
    // Read the payload specified by id and rp into out.
    // The allocated memory is owned by the caller and he is responsible for freeing it.
    // Returns either the length of the string assigned to out or an error.
    int (*read)(const char* id, const char* rp, Data** out);
    int (*write)(const char* id, const char* rp, const char* data);
    int (*del)(const char* id, const char* rp);
} Callbacks;

void* auth_init(Callbacks);
void auth_deinit(void*);

void* ctaphid_init();
void ctaphid_deinit(void*);
void* ctaphid_handle(void*, const char*, size_t, void*);
int ctaphid_iterator_next(void*, char*);
void ctaphid_iterator_deinit(void*);
