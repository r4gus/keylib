#include <stdint.h>
#include <stdlib.h>

typedef enum{
    Error_SUCCESS = 0,
    Error_DoesAlreadyExist = -1,
    Error_DoesNotExist = -2,
    Error_KeyStoreFull = -3,
    Error_OutOfMemory = -4,
    Error_Timeout = -5,
    Error_Other = -6,
} Error;

typedef enum{
    UpResult_Denied = 0,
    UpResult_Accepted = 1,
    UpResult_Timeout = 2,
} UpResult;

typedef struct{
    int (*up)(const char* info, const char* user, const char* rp);
    int (*uv)(const char* info, const char* user, const char* rp);
    int (*select)(const char* rpId, char** users);
    // Read the payload specified by id and rp into out.
    // The allocated memory is owned by the caller and he is responsible for freeing it.
    // Returns either the length of the string assigned to out or an error.
    int (*read)(const char* id, const char* rp, char*** out);
    int (*write)(const char* id, const char* rp, const char* data);
    int (*del)(const char* id);
} Callbacks;

void* auth_init(Callbacks);
void auth_deinit(void*);

void* ctaphid_init();
void ctaphid_deinit(void*);
void* ctaphid_handle(void*, const char*, size_t, void*);
int ctaphid_iterator_next(void*, char*);
void ctaphid_iterator_deinit(void*);
