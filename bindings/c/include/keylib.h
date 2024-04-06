#include <stdint.h>
#include <stdlib.h>

typedef enum{
    // The given operation was successful
    Error_SUCCESS = 0,
    // The given value already exists
    Error_DoesAlreadyExist = -1,
    // The requested value doesn't exist
    Error_DoesNotExist = -2,
    // Credentials can't be inserted into the key-store
    Error_KeyStoreFull = -3,
    // The client ran out of memory
    Error_OutOfMemory = -4,
    // The operation timed out
    Error_Timeout = -5,
    // Unspecified operation
    Error_Other = -6,
} Error;

typedef enum{
    // The user has denied the action
    UpResult_Denied = 0,
    // The user has accepted the action
    UpResult_Accepted = 1,
    // The user presence check has timed out
    UpResult_Timeout = 2,
} UpResult;

typedef enum{
    // The user has denied the action
    UvResult_Denied = 0,
    // The user has accepted the action
    UvResult_Accepted = 1,
    // The user has accepted the action
    UvResult_AcceptedWithUp = 2,
    // The user presence check has timed out
    UvResult_Timeout = 3,
} UvResult;

typedef enum{
    Transports_usb = 1,
    Transports_nfc = 2,
    Transports_ble = 4,
} Transports;

typedef struct{
    // User presence request; user and rp might be NULL!
    UpResult (*up)(const char* info, const char* user, const char* rp);
    // User verification request; user and rp might be NULL!
    UvResult (*uv)(const char* info, const char* user, const char* rp);
    // Callback for selecting a user account.
    // The platform is expected to return the index of the selected user or an error.
    int (*select)(const char* rpId, char** users);
    // Read the payload specified by id and rp into out.
    // The allocated memory is owned by the caller and he is responsible for freeing it.
    // Returns either the length of the string assigned to out or an error.
    int (*read)(const char* id, const char* rp, char*** out);
    // Persist the given data; the id is considered unique.
    int (*write)(const char* id, const char* rp, const char* data);
    // Delete the entry with the given id.
    int (*del)(const char* id);
} Callbacks;

typedef struct{
    // A UUID/ String representing the type of authenticator.
    char aaguid[16];
} AuthSettings;

void* auth_init(Callbacks);
void auth_deinit(void*);
void auth_handle(void*, void*);

void* ctaphid_init();
void ctaphid_deinit(void*);
void* ctaphid_handle(void*, const char*, size_t);
void* ctaphid_iterator(void*);
int ctaphid_iterator_next(void*, char*);
void ctaphid_iterator_deinit(void*);
