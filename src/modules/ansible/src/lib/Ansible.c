// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <stdatomic.h>
#include <version.h>
#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>
#include <parson.h>

#include "Ansible.h"
#include "AnsibleUtils.h"
#include "JsonUtils.h"

// static const char* g_serviceComponentName = "Service";
// static const char* g_userComponentName = "User";

// static const char* g_serviceReportedObjectNames[] = {"rcctl", "systemd", "sysv", "upstart", "src"};
// static const char* g_userReportedObjectNames[] = {"users", "groups"};

// static const char* g_serviceDesiredObjectNames[] = {"desiredServices"};
// static const char* g_userDesiredObjectNames[] = {"desiredUsers", "desiredGroups"};

// static const char* g_serviceAnsibleCollectionName = "ansible.builtin";
// static const char* g_userAnsibleCollectionName = "ansible.builtin";

// static const char* g_serviceAnsibleModuleName = "ansible.service_facts";


// Not call at all, to be generic?
// Be in charge of calling multiple times?

// get run it... 

// What if you have an array, desiredservice, to run for many
// What if you want to build reported from multipe assets

typedef struct ANSIBLE_DESIRED_OBJECT {
    const char componentName[64];
    const char objectName[64];
    const char ansibleCollectionName[64];
    const char ansibleModuleName[64];
    int (*const handler)(const struct ANSIBLE_DESIRED_OBJECT* object, const char* payload);
} ANSIBLE_DESIRED_OBJECT;

typedef struct ANSIBLE_REPORTED_OBJECT {
    const char componentName[64];
    const char objectName[64];
    const char ansibleCollectionName[64];
    const char ansibleModuleName[64];
    const char ansibleModuleArguments[64];
    int (*const handler)(const struct ANSIBLE_REPORTED_OBJECT* object, char** result);
} ANSIBLE_REPORTED_OBJECT;

static const ANSIBLE_REPORTED_OBJECT g_reportedObjects[] = {
    {"Service", "systemd", "ansible.builtin", "service_facts", "", NULL},
    {"Service", "src", "ansible.builtin", "service_facts", "", NULL},
    {"User", "users", "ansible.builtin", "getent", "database=passwd", NULL}};

typedef struct OBJECT_MAPPING
{
    const char mimComponentName[64];
    const char mimObjectName[64];
    const bool mimDesired;
    const char ansibleCollectionName[64];
    const char ansibleModuleName[64];
    const char ansibleModuleArguments[64];
} OBJECT_MAPPING;

static const OBJECT_MAPPING g_objectMappings[] = {
    {"Service", "rcctl", false, "ansible.builtin", "service_facts", ""},
    {"Service", "systemd", false, "ansible.builtin", "service_facts", ""},
    {"Service", "sysv", false, "ansible.builtin", "service_facts", ""},
    {"Service", "upstart", false, "ansible.builtin", "service_facts", ""},
    {"Service", "src", false, "ansible.builtin", "service_facts", ""},
    {"Service", "desiredServices", true, "ansible.builtin", "service", ""},
    {"User", "users", true, "ansible.builtin", "getent", "database=passwd"},
    {"User", "groups", true, "ansible.builtin", "getent", "database=group"},
    {"Docker", "images", false, "community.docker", "docker_image_info", ""}};

static const char* g_ansibleModuleInfo = "{\"Name\": \"Ansible\","
    "\"Description\": \"Provides functionality to observe and configure Ansible\","
    "\"Manufacturer\": \"Microsoft\","
    "\"VersionMajor\": 1,"
    "\"VersionMinor\": 0,"
    "\"VersionInfo\": \"Zinc\","
    "\"Components\": [\"Service\"],"
    "\"Lifetime\": 2,"
    "\"UserAccount\": 0}";

static const char* g_ansibleModuleName = "Ansible module";

static atomic_int g_referenceCount = 0;
static unsigned int g_maxPayloadSizeBytes = 0;

static const char* g_ansibleLogFile = "/var/log/osconfig_ansible.log";
static const char* g_ansibleRolledLogFile = "/var/log/osconfig_ansible.bak";

static OSCONFIG_LOG_HANDLE g_log = NULL;
static bool g_enabled = false;

static OSCONFIG_LOG_HANDLE AnsibleGetLog()
{
    return g_log;
}

static bool AnsibleIsValidSession(MMI_HANDLE clientSession)
{
    return ((NULL == clientSession) || (0 != strcmp(g_ansibleModuleName, (char*)clientSession)) || (g_referenceCount <= 0)) ? false : true;
}

static const OBJECT_MAPPING* AnsibleGetObjectMapping(const char* componentName, const char* objectName, bool desired)
{
    for (size_t i = 0; i < ARRAY_SIZE(g_objectMappings); i++)
    {
        if ((0 == strcmp(g_objectMappings[i].mimComponentName, componentName)) &&
            (0 == strcmp(g_objectMappings[i].mimObjectName, objectName)) &&
            (g_objectMappings[i].mimDesired == desired))
        {
            return &g_objectMappings[i];
        }
    }
    return NULL;
}

static const char* AnsibleGetCollectionName(const char* componentName, const char* objectName, bool desired)
{
    const OBJECT_MAPPING* objectMapping = NULL;
    if (NULL != (objectMapping = AnsibleGetObjectMapping(componentName, objectName, desired)))
    {
        return objectMapping->ansibleCollectionName;
    }
    return NULL;
}

static const char* AnsibleGetModuleName(const char* componentName, const char* objectName, bool desired)
{
    const OBJECT_MAPPING* objectMapping = NULL;
    if (NULL != (objectMapping = AnsibleGetObjectMapping(componentName, objectName, desired)))
    {
        return objectMapping->ansibleModuleName;
    }
    return NULL;
}

static const char* AnsibleGetModuleArguments(const char* componentName, const char* objectName, bool desired)
{
    const OBJECT_MAPPING* objectMapping = NULL;
    if (NULL != (objectMapping = AnsibleGetObjectMapping(componentName, objectName, desired)))
    {
        return objectMapping->ansibleModuleArguments;
    }
    return NULL;
}

void AnsibleInitialize()
{
    g_log = OpenLog(g_ansibleLogFile, g_ansibleRolledLogFile);

    if ((g_enabled = (MMI_OK == AnsibleCheckDependencies(AnsibleGetLog()))))
    {
        for (size_t i = 0; i < ARRAY_SIZE(g_objectMappings); i++)
        {
            if (MMI_OK != AnsibleCheckCollection(g_objectMappings[i].ansibleCollectionName, AnsibleGetLog()))
            {
                g_enabled = false;
                break;
            }
        }
    }

    if (!g_enabled)
    {
        OsConfigLogError(AnsibleGetLog(), "%s failed to find dependencies", g_ansibleModuleName);
    }

    OsConfigLogInfo(AnsibleGetLog(), "%s initialized", g_ansibleModuleName);
}

void AnsibleShutdown(void)
{
    OsConfigLogInfo(AnsibleGetLog(), "%s shutting down", g_ansibleModuleName);

    g_enabled = false;
    CloseLog(&g_log);
}

MMI_HANDLE AnsibleMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    MMI_HANDLE handle = (MMI_HANDLE)g_ansibleModuleName;
    g_maxPayloadSizeBytes = maxPayloadSizeBytes;
    ++g_referenceCount;
    OsConfigLogInfo(AnsibleGetLog(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, handle);
    return handle;
}

void AnsibleMmiClose(MMI_HANDLE clientSession)
{
    if (AnsibleIsValidSession(clientSession))
    {
        --g_referenceCount;
        OsConfigLogInfo(AnsibleGetLog(), "MmiClose(%p)", clientSession);
    }
    else
    {
        OsConfigLogError(AnsibleGetLog(), "MmiClose() called outside of a valid session");
    }
}

int AnsibleMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = EINVAL;

    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return status;
    }

    *payloadSizeBytes = (int)strlen(g_ansibleModuleInfo);
    *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
    if (*payload)
    {
        memset(*payload, 0, *payloadSizeBytes);
        memcpy(*payload, g_ansibleModuleInfo, *payloadSizeBytes);
        status = MMI_OK;
    }
    else
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGetInfo failed to allocate %d bytes", *payloadSizeBytes);
        *payloadSizeBytes = 0;
        status = ENOMEM;
    }

    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AnsibleGetLog(), "MmiGetInfo(%s, %.*s, %d) returning %d", clientName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int AnsibleMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = MMI_OK;
    char* result = NULL;

    const char* ansibleCollectionName = NULL;
    const char* ansibleModuleName = NULL;
    const char* ansibleModuleArguments = NULL;

    JSON_Value* rootValue = NULL;
    JSON_Object* rootObject = NULL;
    JSON_Value* resultValue = NULL;

    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        status = EINVAL;
        return status;
    }

    *payload = NULL;
    *payloadSizeBytes = 0;

    ansibleCollectionName = AnsibleGetCollectionName(componentName, objectName, false);
    ansibleModuleName = AnsibleGetModuleName(componentName, objectName, false);
    ansibleModuleArguments = AnsibleGetModuleArguments(componentName, objectName, false);

    if (!AnsibleIsValidSession(clientSession))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) called outside of a valid session", componentName, objectName);
        status = EINVAL;
    }
    else if (!g_enabled)
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) called outside of valid environment", componentName, objectName);
        status = EINVAL;
    }
    else if ((NULL == ansibleCollectionName) || (NULL == ansibleModuleName))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) called with unsupported component name or object name", componentName, objectName);
        status = EINVAL;
    }
    else if ((MMI_OK != AnsibleExecuteModule(ansibleCollectionName, ansibleModuleName, ansibleModuleArguments, &result, AnsibleGetLog()) || (NULL == result)))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) failed to execute Ansible module", componentName, objectName);
        status = EINVAL;
    }
    else if (NULL == (rootValue = json_parse_string(result)))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) failed to parse JSON string '%s'", componentName, objectName, result);
        status = EINVAL;
    }
    else if (NULL == (rootObject = json_value_get_object(rootValue)))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) failed to find root JSON object", componentName, objectName);
        status = EINVAL;
    }
    else
    {
        // Command result has been parsed and the variable can be repurposed.
        FREE_MEMORY(result);

        if (0 == strcmp(componentName, "Service"))
        {
            resultValue = json_value_deep_copy(json_object_dotget_value(rootObject, "ansible_facts.services"));

            if (NULL != resultValue)
            {
                RemoveObjectsWithPropertyValueNotEqual(resultValue, "source", objectName);
                RemoveObjectsWithPropertyValueNotEqual(resultValue, "state", "running");
                ConvertObjectArrayPropertyValueToArray(&resultValue, "name");
            }
            else
            {
                OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) failed to find JSON object '%s'", componentName, objectName, "ansible_facts.services");
                status = EINVAL;
            }
        }
        else if (0 == strcmp(componentName, "Docker"))
        {
            // TODO: ...
        }
        else if (0 == strcmp(componentName, "User"))
        {
            // TODO: ...
        }

        if (NULL != resultValue)
        {
            result = json_serialize_to_string(resultValue);
        }
    }

    if (MMI_OK != status)
    {
        status = MMI_OK;
        result = "";
    }

    if (NULL != result)
    {
        *payloadSizeBytes = strlen(result);
        if ((g_maxPayloadSizeBytes > 0) && ((unsigned)*payloadSizeBytes > g_maxPayloadSizeBytes))
        {
            OsConfigLogError(AnsibleGetLog(), "MmiGet(%s, %s) insufficient maxmimum size (%d bytes) versus data size (%d bytes), reported value will be truncated", componentName, objectName, g_maxPayloadSizeBytes, *payloadSizeBytes);
            *payloadSizeBytes = g_maxPayloadSizeBytes;
        }

        *payload = (MMI_JSON_STRING)malloc(*payloadSizeBytes);
        if (NULL != *payload)
        {
            memset(*payload, 0, *payloadSizeBytes);
            memcpy(*payload, result, *payloadSizeBytes);
        }
        else
        {
            OsConfigLogError(AnsibleGetLog(), "MmiGet failed to allocate %d bytes", *payloadSizeBytes + 1);
            *payloadSizeBytes = 0;
            status = ENOMEM;
        }
    }

    if (NULL != rootValue)
    {
        json_value_free(rootValue);
    }

    if (NULL != resultValue)
    {
        json_value_free(resultValue);
    }

    if (IsFullLoggingEnabled())
    {
        OsConfigLogInfo(AnsibleGetLog(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, status);
    }

    return status;
}

int AnsibleMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    int status = MMI_OK;
    char *buffer = NULL;

    const char* ansibleCollectionName = NULL;
    const char* ansibleModuleName = NULL;
    char *ansibleModuleArguments = NULL;

    JSON_Value* rootValue = NULL;

    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (payloadSizeBytes <= 0))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s, %p, %d) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        status = EINVAL;
        return status;
    }

    ansibleCollectionName = AnsibleGetCollectionName(componentName, objectName, true);
    ansibleModuleName = AnsibleGetModuleName(componentName, objectName, true);

    if (!AnsibleIsValidSession(clientSession))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s) called outside of a valid session", componentName, objectName);
        status = EINVAL;
    }
    else if (!g_enabled)
    {
        OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s) called outside of valid environment", componentName, objectName);
        status = EINVAL;
    }
    else if ((NULL == ansibleCollectionName) || (NULL == ansibleModuleName))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s) called with unsupported component name or object name", componentName, objectName);
        status = EINVAL;
    }
    else if (NULL == (buffer = malloc(payloadSizeBytes + 1)))
    {
        OsConfigLogError(AnsibleGetLog(), "MmiSet failed to allocate %d bytes", payloadSizeBytes + 1);
        status = ENOMEM;
    }
    else
    {
        memset(buffer, 0, payloadSizeBytes + 1);
        memcpy(buffer, payload, payloadSizeBytes);

        if (NULL != (rootValue = json_parse_string(buffer)))
        {
            if (0 == strcmp(componentName, "Service"))
            {
                ConvertObjectArrayToKeyValuePairString(rootValue, &ansibleModuleArguments);
            }
            else if (0 == strcmp(componentName, "Docker"))
            {
                // TODO: ...
            }
            else if (0 == strcmp(componentName, "User"))
            {
                // TODO: ...
            }

            if ((NULL == ansibleModuleArguments) || (MMI_OK != AnsibleExecuteModule(ansibleCollectionName, ansibleModuleName, ansibleModuleArguments, NULL, AnsibleGetLog())))
            {
                OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s) failed to execute Ansible module", componentName, objectName);
                status = EINVAL;
            }
        }
        else
        {
            OsConfigLogError(AnsibleGetLog(), "MmiSet(%s, %s) failed to parse JSON string '%s'", componentName, objectName, buffer);
            status = EINVAL;
        }
    }

    FREE_MEMORY(buffer);
    FREE_MEMORY(ansibleModuleArguments);

    OsConfigLogInfo(AnsibleGetLog(), "MmiSet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes, status);

    return status;
}

void AnsibleMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}
