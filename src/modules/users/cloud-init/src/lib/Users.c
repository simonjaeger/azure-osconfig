// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <regex.h>
#include <parson.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "Users.h"

static const char* g_usersModuleInfo = "{\"Name\": \"Users\","
    "\"Description\": \"Provides functionality to observe and configure users\","
    "\"Manufacturer\": \"Microsoft\","
    "\"VersionMajor\": 1,"
    "\"VersionMinor\": 0,"
    "\"VersionInfo\": \"Copper\","
    "\"Components\": [\"Users\"],"
    "\"Lifetime\": 2,"
    "\"UserAccount\": 0}";

static const char* g_usersModuleName = "Users module";
static const char* g_usersComponentName = "Users";

static const char* g_desiredUsersObjectName = "desiredUsers";

static const char *g_moduleName = "cc_users_groups";
static const char *g_configJsonPropertyName = "users";

static const char* g_searchCommand = "find '%s' -name '%s' -executable -maxdepth 1 | head -n 1 | tr -d '\n'";
static const char *g_searchDirectories[] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin"};
static const unsigned int g_searchDirectoriesCount = ARRAY_SIZE(g_searchDirectories);
static const char* g_pythonCommand = "cat %s | %s %s %s %s";
static const char* g_pipShowCommand = "%s show '%s' &> /dev/null ; echo $? | tr -d '\n'";

static char* g_executablePython = NULL;
static char* g_executablePip = NULL;
static bool g_valid = false;
static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_usersLogFile = "/var/log/osconfig_users.log";
static const char* g_usersRolledLogFile = "/var/log/osconfig_users.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;

static OSCONFIG_LOG_HANDLE UsersGetLog()
{
    return g_log;
}

char* FindExecutable(const char* name, void* log)
{
    char buffer[128] = {0};
    char* result = NULL;
    struct stat st = {0};

    if ((NULL != name))
    {
        for (unsigned int i = 0; i < g_searchDirectoriesCount; i++)
        {
            memset(buffer, 0, sizeof(buffer));
            snprintf(buffer, sizeof(buffer), g_searchCommand, g_searchDirectories[i], name);

            if ((0 == ExecuteCommand(NULL, buffer, false, false, 0, 0, &result, NULL, log)) &&
                (NULL != result) && (strlen(result) > 0) && (0 == stat(result, &st)))
            {
                break;
            }

            FREE_MEMORY(result);
        }
    }

    return result;
}

bool FindPackage(const char* name, void* log)
{
    bool found = false;
    char buffer[128] = {0};
    char* result = NULL;

    if (NULL != g_executablePip)
    {
        snprintf(buffer, sizeof(buffer), g_pipShowCommand, g_executablePip, name);

        if ((0 == ExecuteCommand(NULL, buffer, false, false, 0, 0, &result, NULL, log)) &&
            (0 == strcmp(result, "0")))
        {
            found = true;
        }
    }

    FREE_MEMORY(result);

    return found;
}

bool ExecuteCloudInit(const char* moduleName, const JSON_Value* propertiesValue, char** result, void* log)
{
    JSON_Value *rootValue = NULL;
    JSON_Object *rootObject = NULL;
    JSON_Value *copiedPropertiesValue = NULL;

    int error = 0;
    char buffer[256] = {0};
    char* tempFile = "/tmp/osconfig-cloud-init-exec-tmp.json";

    // TODO: Generate unique file name.
    // TODO: Get distribution name.

    snprintf(buffer, sizeof(buffer), g_pythonCommand, tempFile, g_executablePython, "/usr/lib/osconfig/cloud-init-exec.py", "ubuntu", moduleName);

    rootValue = json_value_init_object();
    rootObject = json_value_get_object(rootValue);

    if (NULL != propertiesValue)
    {
        copiedPropertiesValue = json_value_deep_copy(propertiesValue);
    }
    else 
    {
        copiedPropertiesValue = json_value_init_object();
    }

    json_object_set_value(rootObject, g_configJsonPropertyName, copiedPropertiesValue);

    json_serialize_to_file(rootValue, tempFile);

    json_value_free(rootValue);

    if (0 != (error = ExecuteCommand(NULL, buffer, false, false, 0, 0, result, NULL, log)))
    {
        OsConfigLogError(log, "ExecuteCloudInit failed with error (%d)", error);
    }

    if (result)
    {
        OsConfigLogInfo(log, "ExecuteCloudInit (%s)", *result);
    }

    return (0 == error);
}

void UsersInitialize()
{
    g_log = OpenLog(g_usersLogFile, g_usersRolledLogFile);

    if (NULL == (g_executablePython = FindExecutable("python3", UsersGetLog())))
    {
        OsConfigLogError(UsersGetLog(), "%s cannot find 'python3' executable", g_usersModuleName);
    }
    else if (NULL == (g_executablePip = FindExecutable("pip3", UsersGetLog())))
    {
        OsConfigLogError(UsersGetLog(), "%s cannot find 'pip' executable", g_usersModuleName);
    }
    else if (false == FindPackage("cloudinit", UsersGetLog()))
    {
        OsConfigLogError(UsersGetLog(), "%s cannot find 'cloudinit' package", g_usersModuleName);
    }
    else 
    {
        g_valid = true;
        OsConfigLogInfo(UsersGetLog(), "%s initialized, using 'python3' '%s'", g_usersModuleName, g_executablePython);
    }
}

void UsersShutdown(void)
{
    FREE_MEMORY(g_executablePython);
    FREE_MEMORY(g_executablePip);

    OsConfigLogInfo(UsersGetLog(), "%s shutting down", g_usersModuleName);

    CloseLog(&g_log);
}

MMI_HANDLE UsersMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    MMI_HANDLE handle = (MMI_HANDLE)g_usersModuleName;
    g_maxPayloadSizeBytes = maxPayloadSizeBytes;
    ++g_referenceCount;
    OsConfigLogInfo(UsersGetLog(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, handle);
    return handle;
}

static bool IsValidSession(MMI_HANDLE clientSession)
{
    return ((NULL == clientSession) || (0 != strcmp(g_usersModuleName, (char*)clientSession)) || (g_referenceCount <= 0)) ? false : true;
}

void UsersMmiClose(MMI_HANDLE clientSession)
{
    if (IsValidSession(clientSession))
    {
        --g_referenceCount;
        OsConfigLogInfo(UsersGetLog(), "MmiClose(%p)", clientSession);
    }
    else 
    {
        OsConfigLogError(UsersGetLog(), "MmiClose() called outside of a valid session");
    }
}

int UsersMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = EINVAL;

    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(UsersGetLog(), "MmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return status;
    }
    
    *payloadSizeBytes = (int)strlen(g_usersModuleInfo);
    *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
    if (*payload)
    {
        memset(*payload, 0, *payloadSizeBytes);
        memcpy(*payload, g_usersModuleInfo, *payloadSizeBytes);
        status = MMI_OK;
    }
    else
    {
        OsConfigLogError(UsersGetLog(), "MmiGetInfo: failed to allocate %d bytes", *payloadSizeBytes);
        *payloadSizeBytes = 0;
        status = ENOMEM;
    }
    
    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(UsersGetLog(), "MmiGetInfo(%s, %.*s, %d) returning %d", clientName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int UsersMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    OsConfigLogInfo(UsersGetLog(), "No reported objects, MmiGet not implemented");
    
    UNUSED(clientSession);
    UNUSED(componentName);
    UNUSED(objectName);
    UNUSED(payload);
    UNUSED(payloadSizeBytes);
    
    return EPERM;
}

int UsersMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    int status = MMI_OK;
    
    char *buffer = NULL;
    JSON_Value* rootValue = NULL;

    if (false == g_valid)
    {
        OsConfigLogError(UsersGetLog(), "%s cannot find dependencies, will not run", g_usersModuleName);
        status = EPERM;
        return status;
    }

    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (payloadSizeBytes <= 0))
    {
        OsConfigLogError(UsersGetLog(), "MmiSet(%s, %s, %p, %d) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        status = EINVAL;
    }
    else if (!IsValidSession(clientSession))
    {
        OsConfigLogError(UsersGetLog(), "MmiSet(%s, %s) called outside of a valid session", componentName, objectName);
        status = EINVAL;
    }
    else if (0 != strcmp(componentName, g_usersComponentName))
    {
        OsConfigLogError(UsersGetLog(), "MmiSet called for an unsupported component name '%s'", componentName);
        status = EINVAL;
    }
    else if (0 != strcmp(objectName, g_desiredUsersObjectName))
    {
        OsConfigLogError(UsersGetLog(), "MmiSet called for an unsupported object name '%s'", objectName);
        status = EINVAL;
    }
    else
    {
        buffer = malloc(payloadSizeBytes + 1);
        if (NULL != buffer)
        {
            memset(buffer, 0, payloadSizeBytes + 1);
            memcpy(buffer, payload, payloadSizeBytes);

            rootValue = json_parse_string(buffer);
            
            if (false == ExecuteCloudInit(g_moduleName, rootValue, NULL, UsersGetLog()))
            {
                OsConfigLogError(UsersGetLog(), "MmiSet failed to execute Cloud-init (module = '%s')", g_moduleName);
                status = EINVAL;
            }
        }
    }

    OsConfigLogInfo(UsersGetLog(), "MmiSet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes, status);

    if (NULL != rootValue)
    {
        json_value_free(rootValue);
    }

    FREE_MEMORY(buffer);

    return status;
}

void UsersMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}
