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

// static const char* g_reportedUsersObjectName = "users";
static const char* g_desiredUsersObjectName = "desiredUsers";

static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_usersConfigFile = NULL;
static const char* g_usersLogFile = "/var/log/osconfig_users.log";
static const char* g_usersRolledLogFile = "/var/log/osconfig_users.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;

static OSCONFIG_LOG_HANDLE UsersGetLog()
{
    return g_log;
}

void UsersInitialize(const char* configFile)
{
    g_usersConfigFile = configFile;
    g_log = OpenLog(g_usersLogFile, g_usersRolledLogFile);
        
    OsConfigLogInfo(UsersGetLog(), "%s initialized", g_usersModuleName);
}

void UsersShutdown(void)
{
    OsConfigLogInfo(UsersGetLog(), "%s shutting down", g_usersModuleName);

    g_usersConfigFile = NULL;
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

    // int status = MMI_OK;

    // if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    // {
    //     OsConfigLogError(UsersGetLog(), "MmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
    //     status = EINVAL;
    //     return status;
    // }

    // *payload = NULL;
    // *payloadSizeBytes = 0;

    // if (!IsValidSession(clientSession))
    // {
    //     OsConfigLogError(UsersGetLog(), "MmiGet(%s, %s) called outside of a valid session", componentName, objectName);
    //     status = EINVAL;
    // }
    // else if (0 != strcmp(componentName, g_usersComponentName))
    // {
    //     OsConfigLogError(UsersGetLog(), "MmiGet called for an unsupported component name '%s'", componentName);
    //     status = EINVAL;
    // }
    // else
    // {
    //     // TODO: ...
    // }

    // if (IsFullLoggingEnabled())
    // {
    //     OsConfigLogInfo(UsersGetLog(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    // }

    // return status;
}

bool UsersExecuteChef(const char* resourceClass, const char* resourceName, const char* action, const JSON_Object* propertiesObject)
{
    JSON_Value *rootValue = NULL;
    JSON_Object *rootObject = NULL;
    JSON_Value *propertiesValue = NULL;
    JSON_Value *copiedPropertiesValue = NULL;

    int error = 0;
    const char* command = "cat /tmp/osconfig-chef-exec-tmp.json | ruby /usr/lib/osconfig/chef-exec.rb";

    rootValue = json_value_init_object();
    rootObject = json_value_get_object(rootValue);

    json_object_set_string(rootObject, "resource_class", resourceClass);
    json_object_set_string(rootObject, "resource_name", resourceName);

    if (NULL != action)
    {
        json_object_set_string(rootObject, "action", action);
    }

    propertiesValue = json_object_get_wrapping_value(propertiesObject);
    copiedPropertiesValue = json_value_deep_copy(propertiesValue);
    json_object_set_value(rootObject, "properties", copiedPropertiesValue);

    json_serialize_to_file(rootValue, "/tmp/osconfig-chef-exec-tmp.json");

    json_value_free(rootValue);

    if (0 != (error = system(command)))
    {
        OsConfigLogError(UsersGetLog(), "Status = %d", error);
    }
    return (0 == error);
}

int UsersMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    int status = MMI_OK;
    
    char *buffer = NULL;
    JSON_Value* rootValue = NULL;
    JSON_Array* rootArray = NULL;
    JSON_Object* currentObject = NULL;

    const char* resourceClass = "user";
    const char* resourceName = NULL;
    int actionSizeBytes = 0;
    char* action = NULL;

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
            if (json_value_get_type(rootValue) == JSONArray)
            {
                rootArray = json_value_get_array(rootValue);
                for (unsigned int i = 0; i < json_array_get_count(rootArray); i++)
                {
                    currentObject = json_array_get_object(rootArray, i);
                    resourceName = json_object_get_string(currentObject, "username");
                    
                    actionSizeBytes = json_object_get_string_len(currentObject, "action") + 1;
                    action = malloc(actionSizeBytes);
                    if (NULL != action)
                    {
                        memset(action, 0, actionSizeBytes);
                        memcpy(action, json_object_get_string(currentObject, "action"), actionSizeBytes);

                        json_object_remove(currentObject, "action");

                        if (false == UsersExecuteChef(resourceClass, resourceName, action, currentObject))
                        {
                            OsConfigLogError(UsersGetLog(), "MmiSet failed to execute Chef (resource_class = '%s', resource_name = '%s', action = '%s')", (NULL != resourceClass) ? resourceClass : "", (NULL != resourceName) ? resourceName : "", (NULL != action) ? action : "");
                        }
                    }
                }
            }
        }
    }

    OsConfigLogInfo(UsersGetLog(), "MmiSet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes, status);

    if (NULL != rootValue)
    {
        json_value_free(rootValue);
    }

    FREE_MEMORY(action);
    FREE_MEMORY(buffer);

    return status;
}

void UsersMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}
